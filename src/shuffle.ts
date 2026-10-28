/**
 * @purr-poker/rng - Unbiased Deterministic Fisher-Yates Shuffle
 *
 * Consumes the deterministic SHAKE256 or HKDF-SHA256 byte stream and executes
 * an unbiased Fisher-Yates (Knuth) shuffle with strict rejection sampling over
 * 32-bit unsigned integers to eliminate modulo bias completely.
 */

import {
  DECK_SIZE,
  type EntropyReveal,
  type FisherYatesStep,
  type KdfMode,
  type SealedCardEnvelope,
  type ShuffleResult,
} from './types.ts';
import { deriveShuffleRandomStream } from './entropy.ts';

const TWO_POW_32 = 0x1_0000_0000; // 4,294,967,296

/**
 * Execute the unbiased Fisher-Yates shuffle over the 52 sealed card envelopes.
 */
export function computeDeterministicShuffle(
  handId: string,
  deckRoot: string,
  initialEnvelopes: SealedCardEnvelope[],
  reveals: EntropyReveal[],
  kdfMode: KdfMode = 'SHAKE256'
): ShuffleResult {
  if (initialEnvelopes.length !== DECK_SIZE) {
    throw new Error(`Expected ${DECK_SIZE} initial envelopes, got ${initialEnvelopes.length}`);
  }

  // 1024 bytes = 256 uint32 words (51 needed in expectation; rejection probability < 52 / 2^32)
  const { masterSeedHex, randomStream } = deriveShuffleRandomStream(
    handId,
    deckRoot,
    reveals,
    kdfMode,
    1024
  );

  const permutation = Array.from({ length: DECK_SIZE }, (_, idx) => idx);
  const steps: FisherYatesStep[] = [];
  let byteOffset = 0;

  const nextUint32 = (): number => {
    if (byteOffset + 4 > randomStream.length) {
      throw new Error('Random stream exhausted during rejection-sampled Fisher-Yates shuffle.');
    }
    const val = randomStream.readUInt32BE(byteOffset);
    byteOffset += 4;
    return val;
  };

  for (let i = DECK_SIZE - 1; i > 0; i--) {
    const range = i + 1;
    // Largest multiple of range <= 2^32. Values >= rejectionLimit are rejected to eliminate modulo bias.
    const rejectionLimit = Math.floor(TWO_POW_32 / range) * range;
    let attempts = 0;
    let randomUint32 = 0;

    do {
      randomUint32 = nextUint32();
      attempts++;
    } while (randomUint32 >= rejectionLimit);

    const j = randomUint32 % range;
    [permutation[i], permutation[j]] = [permutation[j], permutation[i]];

    steps.push({
      i,
      j,
      randomUint32,
      rejectionLimit,
      attempts,
    });
  }

  const shuffledCommitments = permutation.map((envIdx) => initialEnvelopes[envIdx].commitment);
  const shuffledZkCommitments = permutation.map((envIdx) => initialEnvelopes[envIdx].zkCommitment);

  return {
    permutation,
    shuffledCommitments,
    shuffledZkCommitments,
    steps,
    masterSeedHex,
    kdfMode,
  };
}

/**
 * Verify that a claimed permutation array is a valid bijection of [0..51]
 */
export function isValidPermutation52(permutation: number[]): boolean {
  if (!Array.isArray(permutation) || permutation.length !== DECK_SIZE) {
    return false;
  }
  const seen = new Set<number>();
  for (const val of permutation) {
    if (!Number.isInteger(val) || val < 0 || val >= DECK_SIZE || seen.has(val)) {
      return false;
    }
    seen.add(val);
  }
  return seen.size === DECK_SIZE;
}
