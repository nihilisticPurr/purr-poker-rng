/**
 * @purr-poker/rng - 52-Card Salted Commitments & Merkle Tree
 *
 * Each of the 52 sealed envelopes commits to a canonical card (0..51) using a
 * unique 256-bit CSPRNG salt.
 * - Standard commitment: SHA-256("PURR_CARD_V1" || handId || envelopeIdx || cardIdx || salt256)
 * - Algebraic Pedersen commitment: g^(cardIdx + 1) * h^(blindingFromSalt(salt256)) mod P
 *   used by the Zero-Knowledge Deck Bijection & Permutation Proof.
 */

import crypto from 'node:crypto';
import { DECK_SIZE, type SealedCardEnvelope, type SecretCardRecord } from './types.ts';
import { generateSecretInitialDeckOrder, indexToCard } from './cards.ts';
import { computePedersenCardCommitment, deriveBlindingFromSalt } from './zk/pedersen.ts';

const CARD_COMMITMENT_DOMAIN = 'PURR_CARD_V1';
const MERKLE_LEAF_DOMAIN = 'PURR_MERKLE_LEAF_V1';
const MERKLE_NODE_DOMAIN = 'PURR_MERKLE_NODE_V1';

/**
 * Generate a cryptographically secure 256-bit (32-byte) random salt as 64-char hex
 */
export function generateSalt256(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Validate that a hex string is a valid 256-bit (32-byte / 64 hex chars) value
 */
export function assertValidHex256(hex: string, label: string): void {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`Invalid ${label}: expected 64-character hexadecimal string (256 bits).`);
  }
}

/**
 * Compute the SHA-256 commitment for a single sealed card envelope:
 * SHA-256("PURR_CARD_V1" || ":" || handId || ":" || envelopeIndex || ":" || cardIndex || ":" || saltBytes)
 */
export function computeCardCommitment(
  handId: string,
  envelopeIndex: number,
  cardIndex: number,
  saltHex: string
): string {
  assertValidHex256(saltHex, 'card saltHex');
  if (!Number.isInteger(envelopeIndex) || envelopeIndex < 0 || envelopeIndex >= DECK_SIZE) {
    throw new RangeError(`Invalid envelopeIndex: ${envelopeIndex}`);
  }
  if (!Number.isInteger(cardIndex) || cardIndex < 0 || cardIndex >= DECK_SIZE) {
    throw new RangeError(`Invalid cardIndex: ${cardIndex}`);
  }

  const hash = crypto.createHash('sha256');
  hash.update(`${CARD_COMMITMENT_DOMAIN}:${handId}:${envelopeIndex}:${cardIndex}:`, 'utf8');
  hash.update(Buffer.from(saltHex, 'hex'));
  return hash.digest('hex');
}

/**
 * Create all 52 sealed card envelopes with fresh 256-bit salts.
 * If customCardOrder is omitted, the server randomly permutes the 52 cards into the
 * 52 envelopes using CSPRNG before sealing them.
 */
export function createCommittedDeck(
  handId: string,
  customCardOrder?: number[],
  customSaltsHex?: string[]
): {
  secretRecords: SecretCardRecord[];
  publicEnvelopes: SealedCardEnvelope[];
  deckRoot: string;
} {
  const cardOrder = customCardOrder ?? generateSecretInitialDeckOrder();
  if (cardOrder.length !== DECK_SIZE) {
    throw new Error(`Expected ${DECK_SIZE} cards in deck order, got ${cardOrder.length}`);
  }

  const secretRecords: SecretCardRecord[] = [];
  const publicEnvelopes: SealedCardEnvelope[] = [];

  for (let envelopeIndex = 0; envelopeIndex < DECK_SIZE; envelopeIndex++) {
    const cardIndex = cardOrder[envelopeIndex];
    const card = indexToCard(cardIndex);
    const saltHex = customSaltsHex ? customSaltsHex[envelopeIndex] : generateSalt256();
    assertValidHex256(saltHex, `saltHex[${envelopeIndex}]`);

    const commitment = computeCardCommitment(handId, envelopeIndex, cardIndex, saltHex);
    const blinding = deriveBlindingFromSalt(handId, envelopeIndex, saltHex);
    const zkCommitment = computePedersenCardCommitment(cardIndex, blinding).toString(16).padStart(64, '0');

    const record: SecretCardRecord = {
      envelopeIndex,
      cardIndex,
      cardCode: card.code,
      card,
      saltHex,
      commitment,
      zkCommitment,
    };

    secretRecords.push(record);
    publicEnvelopes.push({
      envelopeIndex,
      commitment,
      zkCommitment,
    });
  }

  const deckRoot = computeDeckMerkleRoot(publicEnvelopes);

  return {
    secretRecords,
    publicEnvelopes,
    deckRoot,
  };
}

/**
 * Compute leaf hash for a SealedCardEnvelope in the 64-leaf binary Merkle tree
 */
export function hashEnvelopeLeaf(envelope: SealedCardEnvelope): string {
  return crypto
    .createHash('sha256')
    .update(`${MERKLE_LEAF_DOMAIN}:${envelope.envelopeIndex}:${envelope.commitment}:${envelope.zkCommitment}`, 'utf8')
    .digest('hex');
}

/**
 * Compute internal parent node hash in the binary Merkle tree
 */
function hashMerklePair(leftHex: string, rightHex: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(`${MERKLE_NODE_DOMAIN}:`, 'utf8');
  hash.update(Buffer.from(leftHex, 'hex'));
  hash.update(Buffer.from(rightHex, 'hex'));
  return hash.digest('hex');
}

/**
 * Build the binary Merkle tree layers (padded to next power of 2 = 64 leaves)
 */
function buildMerkleTreeLayers(envelopes: SealedCardEnvelope[]): string[][] {
  if (envelopes.length !== DECK_SIZE) {
    throw new Error(`Expected ${DECK_SIZE} envelopes to build deck Merkle tree, got ${envelopes.length}`);
  }

  const targetLeafCount = 64; // Next power of 2 >= 52
  const zeroLeaf = '0'.repeat(64);
  const leaves: string[] = [];

  for (let i = 0; i < targetLeafCount; i++) {
    if (i < envelopes.length) {
      leaves.push(hashEnvelopeLeaf(envelopes[i]));
    } else {
      leaves.push(zeroLeaf);
    }
  }

  const layers: string[][] = [leaves];
  let currentLayer = leaves;

  while (currentLayer.length > 1) {
    const nextLayer: string[] = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      nextLayer.push(hashMerklePair(currentLayer[i], currentLayer[i + 1]));
    }
    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return layers;
}

/**
 * Compute the 256-bit Merkle root over all 52 initial sealed card envelopes
 */
export function computeDeckMerkleRoot(envelopes: SealedCardEnvelope[]): string {
  const layers = buildMerkleTreeLayers(envelopes);
  return layers[layers.length - 1][0];
}

/**
 * Generate a Merkle inclusion proof for a specific initial envelope index (0..51)
 */
export function generateMerkleProof(
  envelopes: SealedCardEnvelope[],
  envelopeIndex: number
): string[] {
  if (!Number.isInteger(envelopeIndex) || envelopeIndex < 0 || envelopeIndex >= DECK_SIZE) {
    throw new RangeError(`Invalid envelopeIndex for Merkle proof: ${envelopeIndex}`);
  }

  const layers = buildMerkleTreeLayers(envelopes);
  const proof: string[] = [];
  let idx = envelopeIndex;

  for (let level = 0; level < layers.length - 1; level++) {
    const siblingIdx = idx ^ 1;
    proof.push(layers[level][siblingIdx]);
    idx = Math.floor(idx / 2);
  }

  return proof;
}

/**
 * Verify a Merkle inclusion proof for a SealedCardEnvelope against deckRoot
 */
export function verifyMerkleProof(
  envelope: SealedCardEnvelope,
  merkleProof: string[],
  expectedDeckRoot: string
): boolean {
  if (merkleProof.length !== 6) {
    // 64 leaves = 2^6 -> 6 sibling hashes
    return false;
  }

  let currentHash = hashEnvelopeLeaf(envelope);
  let idx = envelope.envelopeIndex;

  for (const siblingHash of merkleProof) {
    if (!/^[0-9a-fA-F]{64}$/.test(siblingHash)) {
      return false;
    }
    if (idx % 2 === 0) {
      currentHash = hashMerklePair(currentHash, siblingHash);
    } else {
      currentHash = hashMerklePair(siblingHash, currentHash);
    }
    idx = Math.floor(idx / 2);
  }

  return currentHash.toLowerCase() === expectedDeckRoot.toLowerCase();
}
