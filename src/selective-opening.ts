/**
 * @purr-poker/rng - Selective Card Opening & Mucked Card Privacy
 *
 * Implements the core privacy guarantee of the PurrPoker Provably Fair protocol:
 * - Only cards a player is entitled to see (their own hole cards, community board cards,
 *   and non-mucked showdown cards) have their 256-bit salts and opening proofs revealed.
 * - Folded and mucked hole cards NEVER have their 256-bit salts revealed, keeping them
 *   information-theoretically and computationally secret forever — even in heads-up pots!
 */

import {
  type CardOpeningProof,
  type DealStage,
  DECK_SIZE,
  type SealedCardEnvelope,
  type SecretCardRecord,
} from './types.ts';
import {
  computeCardCommitment,
  generateMerkleProof,
  verifyMerkleProof,
} from './commitments.ts';
import { indexToCard } from './cards.ts';
import {
  computePedersenCardCommitment,
  deriveBlindingFromSalt,
} from './zk/pedersen.ts';

/**
 * Create a selective CardOpeningProof for a single dealt position in the shuffled deck.
 */
export function createCardOpeningProof(
  handId: string,
  secretRecords: SecretCardRecord[],
  publicEnvelopes: SealedCardEnvelope[],
  permutation: number[],
  shuffledPosition: number,
  recipient: 'public' | string,
  stage: DealStage,
  seatIndex?: number
): CardOpeningProof {
  if (
    !Number.isInteger(shuffledPosition) ||
    shuffledPosition < 0 ||
    shuffledPosition >= DECK_SIZE
  ) {
    throw new RangeError(`Invalid shuffledPosition: ${shuffledPosition}`);
  }

  const initialEnvelopeIndex = permutation[shuffledPosition];
  const record = secretRecords[initialEnvelopeIndex];
  if (!record) {
    throw new Error(`Missing secret record for initialEnvelopeIndex ${initialEnvelopeIndex}`);
  }

  const merkleProof = generateMerkleProof(publicEnvelopes, initialEnvelopeIndex);

  return {
    shuffledPosition,
    initialEnvelopeIndex,
    cardIndex: record.cardIndex,
    cardCode: record.cardCode,
    card: record.card,
    saltHex: record.saltHex,
    commitment: record.commitment,
    zkCommitment: record.zkCommitment,
    merkleProof,
    recipient,
    stage,
    seatIndex,
  };
}

/**
 * Verify a single CardOpeningProof against the locked deckRoot, initialEnvelopes, and permutation.
 */
export function verifyCardOpeningProof(
  handId: string,
  deckRoot: string,
  initialEnvelopes: SealedCardEnvelope[],
  permutation: number[],
  opening: CardOpeningProof
): { valid: boolean; error?: string } {
  try {
    const { shuffledPosition, initialEnvelopeIndex, cardIndex, saltHex, commitment, zkCommitment, merkleProof } =
      opening;

    if (
      !Number.isInteger(shuffledPosition) ||
      shuffledPosition < 0 ||
      shuffledPosition >= DECK_SIZE
    ) {
      return { valid: false, error: `Invalid shuffledPosition: ${shuffledPosition}` };
    }

    const expectedEnvelopeIdx = permutation[shuffledPosition];
    if (initialEnvelopeIndex !== expectedEnvelopeIdx) {
      return {
        valid: false,
        error: `Dealt position ${shuffledPosition} maps to envelope ${expectedEnvelopeIdx} in permutation, but opening claims ${initialEnvelopeIndex}.`,
      };
    }

    const lockedEnvelope = initialEnvelopes[initialEnvelopeIndex];
    if (!lockedEnvelope) {
      return { valid: false, error: `Envelope ${initialEnvelopeIndex} not found in initialEnvelopes.` };
    }

    if (
      lockedEnvelope.commitment.toLowerCase() !== commitment.toLowerCase() ||
      lockedEnvelope.zkCommitment.toLowerCase() !== zkCommitment.toLowerCase()
    ) {
      return {
        valid: false,
        error: `Opening commitment for position ${shuffledPosition} does not match locked envelope #${initialEnvelopeIndex}.`,
      };
    }

    // Recompute SHA-256 salted commitment
    const recomputedShaCommitment = computeCardCommitment(
      handId,
      initialEnvelopeIndex,
      cardIndex,
      saltHex
    );
    if (recomputedShaCommitment.toLowerCase() !== lockedEnvelope.commitment.toLowerCase()) {
      return {
        valid: false,
        error: `SHA-256 commitment verification failed for position ${shuffledPosition} (envelope #${initialEnvelopeIndex}).`,
      };
    }

    // Recompute ZK algebraic Pedersen commitment from the same saltHex
    const blinding = deriveBlindingFromSalt(handId, initialEnvelopeIndex, saltHex);
    const recomputedZkCommitment = computePedersenCardCommitment(cardIndex, blinding)
      .toString(16)
      .padStart(64, '0');
    if (recomputedZkCommitment.toLowerCase() !== lockedEnvelope.zkCommitment.toLowerCase()) {
      return {
        valid: false,
        error: `Algebraic ZK Pedersen commitment mismatch for position ${shuffledPosition} (envelope #${initialEnvelopeIndex}).`,
      };
    }

    // Verify canonical card code
    const expectedCard = indexToCard(cardIndex);
    if (opening.cardCode !== expectedCard.code) {
      return {
        valid: false,
        error: `Card code mismatch: cardIndex ${cardIndex} is ${expectedCard.code}, but opening says ${opening.cardCode}.`,
      };
    }

    // Verify Merkle inclusion proof against deckRoot
    const merkleOk = verifyMerkleProof(lockedEnvelope, merkleProof, deckRoot);
    if (!merkleOk) {
      return {
        valid: false,
        error: `Merkle proof verification failed against deckRoot for envelope #${initialEnvelopeIndex}.`,
      };
    }

    return { valid: true };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
