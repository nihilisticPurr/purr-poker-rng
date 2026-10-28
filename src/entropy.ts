/**
 * @purr-poker/rng - Multi-Party 256-bit Entropy Commit-Reveal & KDF (SHAKE256 / HKDF)
 *
 * Protocol:
 * 1. Before locking: Server + all players commit to 256-bit entropy seeds.
 * 2. After locking: Server + all players reveal their 256-bit entropy seeds.
 * 3. Master Seed & deterministic byte stream are derived via SHAKE256 or HKDF-SHA256
 *    bound to (handId, deckRoot, serverEntropy, playerEntropies...).
 */

import crypto from 'node:crypto';
import type { EntropyCommitment, EntropyReveal, KdfMode } from './types.ts';
import { assertValidHex256 } from './commitments.ts';

const ENTROPY_COMMITMENT_DOMAIN = 'PURR_ENTROPY_V1';
const SHUFFLE_TRANSCRIPT_DOMAIN = 'PURR_SHUFFLE_SEED_V1';

/**
 * Generate a fresh 256-bit (32-byte) CSPRNG entropy seed as 64-character hex
 */
export function generateEntropy256(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Compute the SHA-256 commitment hash for a participant's 256-bit entropy seed
 */
export function computeEntropyCommitmentHash(
  handId: string,
  participantId: string,
  entropyHex: string
): string {
  assertValidHex256(entropyHex, `entropyHex for ${participantId}`);
  const hash = crypto.createHash('sha256');
  hash.update(`${ENTROPY_COMMITMENT_DOMAIN}:${handId}:${participantId}:`, 'utf8');
  hash.update(Buffer.from(entropyHex, 'hex'));
  return hash.digest('hex');
}

/**
 * Create a Phase-1 EntropyCommitment record
 */
export function createEntropyCommitment(
  handId: string,
  participantId: string,
  role: 'server' | 'player',
  entropyHex: string,
  seatIndex?: number,
  committedAt: number = Date.now()
): EntropyCommitment {
  return {
    participantId,
    role,
    seatIndex,
    commitmentHash: computeEntropyCommitmentHash(handId, participantId, entropyHex),
    committedAt,
  };
}

/**
 * Verify that all revealed entropy seeds match their pre-locked commitments
 */
export function verifyEntropyCommitmentsAndReveals(
  handId: string,
  commitments: EntropyCommitment[],
  reveals: EntropyReveal[]
): { valid: boolean; error?: string } {
  if (commitments.length === 0) {
    return { valid: false, error: 'No entropy commitments present.' };
  }
  if (commitments.length !== reveals.length) {
    return {
      valid: false,
      error: `Commitment count (${commitments.length}) does not match reveal count (${reveals.length}).`,
    };
  }

  const hasServer = commitments.some((c) => c.role === 'server');
  if (!hasServer) {
    return { valid: false, error: 'Missing required server entropy commitment.' };
  }

  const revealMap = new Map<string, EntropyReveal>();
  for (const rev of reveals) {
    if (revealMap.has(rev.participantId)) {
      return { valid: false, error: `Duplicate entropy reveal for participant "${rev.participantId}".` };
    }
    revealMap.set(rev.participantId, rev);
  }

  for (const com of commitments) {
    const rev = revealMap.get(com.participantId);
    if (!rev) {
      return {
        valid: false,
        error: `Missing entropy reveal for committed participant "${com.participantId}".`,
      };
    }
    if (rev.role !== com.role || rev.seatIndex !== com.seatIndex) {
      return {
        valid: false,
        error: `Metadata mismatch between commitment and reveal for "${com.participantId}".`,
      };
    }
    if (rev.revealedAt < com.committedAt) {
      return {
        valid: false,
        error: `Reveal timestamp (${rev.revealedAt}) precedes commitment timestamp (${com.committedAt}) for "${com.participantId}".`,
      };
    }

    try {
      const expectedHash = computeEntropyCommitmentHash(handId, com.participantId, rev.entropyHex);
      if (expectedHash.toLowerCase() !== com.commitmentHash.toLowerCase()) {
        return {
          valid: false,
          error: `Entropy commitment mismatch for participant "${com.participantId}". Expected ${com.commitmentHash}, got ${expectedHash}.`,
        };
      }
    } catch (err) {
      return {
        valid: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  return { valid: true };
}

/**
 * Canonicalize entropy reveals so server is first, followed by players ordered by
 * (seatIndex ASC, participantId ASC).
 */
export function canonicalizeEntropyReveals(reveals: EntropyReveal[]): EntropyReveal[] {
  return [...reveals].sort((a, b) => {
    if (a.role !== b.role) {
      return a.role === 'server' ? -1 : 1;
    }
    const seatA = a.seatIndex ?? Number.MAX_SAFE_INTEGER;
    const seatB = b.seatIndex ?? Number.MAX_SAFE_INTEGER;
    if (seatA !== seatB) {
      return seatA - seatB;
    }
    return a.participantId.localeCompare(b.participantId);
  });
}

/**
 * Serialize the canonical shuffle transcript buffer binding:
 * - Domain tag ("PURR_SHUFFLE_SEED_V1")
 * - handId
 * - deckRoot (Merkle root of the 52 sealed card commitments)
 * - Ordered participant reveals (server first, then players by seat/ID)
 */
export function buildCanonicalTranscriptBuffer(
  handId: string,
  deckRoot: string,
  reveals: EntropyReveal[]
): Buffer {
  assertValidHex256(deckRoot, 'deckRoot');
  const ordered = canonicalizeEntropyReveals(reveals);
  const chunks: Buffer[] = [
    Buffer.from(`${SHUFFLE_TRANSCRIPT_DOMAIN}|hand:${handId}|deckRoot:${deckRoot.toLowerCase()}|count:${ordered.length}|`, 'utf8'),
  ];

  for (const rev of ordered) {
    assertValidHex256(rev.entropyHex, `entropyHex (${rev.participantId})`);
    chunks.push(
      Buffer.from(`${rev.role}:${rev.seatIndex ?? -1}:${rev.participantId}:`, 'utf8'),
      Buffer.from(rev.entropyHex, 'hex'),
      Buffer.from('|', 'utf8')
    );
  }

  return Buffer.concat(chunks);
}

/**
 * Derive the 256-bit Master Shuffle Seed and an extendable deterministic random byte stream
 * using either SHAKE256 (NIST FIPS 202 XOF) or HKDF-SHA256 (RFC 5869).
 */
export function deriveShuffleRandomStream(
  handId: string,
  deckRoot: string,
  reveals: EntropyReveal[],
  kdfMode: KdfMode = 'SHAKE256',
  streamByteLength: number = 1024
): {
  masterSeedHex: string;
  randomStream: Buffer;
} {
  const transcript = buildCanonicalTranscriptBuffer(handId, deckRoot, reveals);

  if (kdfMode === 'SHAKE256') {
    // First 32 bytes (256 bits) = masterSeedHex; remaining bytes = Fisher-Yates random stream
    const totalBytes = 32 + streamByteLength;
    const xofOutput = crypto
      .createHash('shake256', { outputLength: totalBytes })
      .update(transcript)
      .digest();

    return {
      masterSeedHex: xofOutput.subarray(0, 32).toString('hex'),
      randomStream: xofOutput.subarray(32, totalBytes),
    };
  }

  if (kdfMode === 'HKDF-SHA256') {
    const salt = Buffer.from(deckRoot, 'hex');
    const masterKeyBuf = Buffer.from(
      crypto.hkdfSync('sha256', transcript, salt, Buffer.from('PURR_MASTER_SEED_V1', 'utf8'), 32)
    );
    const masterSeedHex = masterKeyBuf.toString('hex');

    // Expand deterministic blocks in counter mode if streamByteLength > 255 * 32
    const blocks: Buffer[] = [];
    let bytesRemaining = streamByteLength;
    let epoch = 0;

    while (bytesRemaining > 0) {
      const chunkLen = Math.min(bytesRemaining, 255 * 32);
      const info = Buffer.from(`PURR_FISHER_YATES_STREAM_V1:epoch:${epoch}`, 'utf8');
      const chunk = Buffer.from(crypto.hkdfSync('sha256', masterKeyBuf, salt, info, chunkLen));
      blocks.push(chunk);
      bytesRemaining -= chunkLen;
      epoch++;
    }

    return {
      masterSeedHex,
      randomStream: Buffer.concat(blocks, streamByteLength),
    };
  }

  throw new Error(`Unsupported KDF mode: ${String(kdfMode)}`);
}
