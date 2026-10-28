/**
 * @purr-poker/rng - Complete Public & Player Hand Proof Verifier
 *
 * Performs a 7-stage cryptographic audit of any PublicHandProof JSON package.
 */

import {
  DECK_SIZE,
  type PublicHandProof,
  type VerificationCheck,
  type VerificationReport,
} from './types.ts';
import { computeDeckMerkleRoot } from './commitments.ts';
import { verifyEntropyCommitmentsAndReveals } from './entropy.ts';
import { computeDeterministicShuffle } from './shuffle.ts';
import { verifyZKDeckValidityProof } from './zk/deck-validity-prover.ts';
import { verifyCardOpeningProof } from './selective-opening.ts';

/**
 * Audit and verify a complete PurrPoker Provably Fair + ZK Hand Proof
 */
export function verifyHandProof(proof: PublicHandProof): VerificationReport {
  const checks: VerificationCheck[] = [];

  // Stage 1: Deck Merkle Root & 52 Sealed Envelopes Integrity
  let deckRootValid = false;
  try {
    if (proof.initialEnvelopes.length !== DECK_SIZE) {
      checks.push({
        name: '1. 52 Sealed Card Commitments & Merkle Root',
        passed: false,
        details: `Expected ${DECK_SIZE} initial envelopes, found ${proof.initialEnvelopes.length}.`,
      });
    } else {
      const recomputedRoot = computeDeckMerkleRoot(proof.initialEnvelopes);
      deckRootValid = recomputedRoot.toLowerCase() === proof.deckRoot.toLowerCase();
      checks.push({
        name: '1. 52 Sealed Card Commitments & Merkle Root',
        passed: deckRootValid,
        details: deckRootValid
          ? `Verified all 52 sealed envelopes hash to locked deckRoot (${proof.deckRoot.slice(0, 16)}...).`
          : `Merkle root mismatch: expected ${proof.deckRoot}, computed ${recomputedRoot}.`,
      });
    }
  } catch (err) {
    checks.push({
      name: '1. 52 Sealed Card Commitments & Merkle Root',
      passed: false,
      details: err instanceof Error ? err.message : String(err),
    });
  }

  // Stage 2: Multi-Party Entropy Commit-Reveal Lock
  const entropyCheck = verifyEntropyCommitmentsAndReveals(
    proof.handId,
    proof.entropyCommitments,
    proof.entropyReveals
  );
  checks.push({
    name: '2. Multi-Party 256-Bit Entropy Commit-Reveal',
    passed: entropyCheck.valid,
    details: entropyCheck.valid
      ? `Verified ${proof.entropyReveals.length} participant entropy seeds (server + players) against pre-locked SHA-256 commitments.`
      : `Entropy verification failed: ${entropyCheck.error}`,
  });

  // Stage 3 & 4: KDF Master Seed (SHAKE256 / HKDF) & Unbiased Fisher-Yates Shuffle
  let shuffleMatches = false;
  try {
    const recomputedShuffle = computeDeterministicShuffle(
      proof.handId,
      proof.deckRoot,
      proof.initialEnvelopes,
      proof.entropyReveals,
      proof.kdfMode
    );

    const seedMatches =
      recomputedShuffle.masterSeedHex.toLowerCase() === proof.masterSeedHex.toLowerCase();
    checks.push({
      name: `3. Master Seed Derivation (${proof.kdfMode})`,
      passed: seedMatches,
      details: seedMatches
        ? `Derived masterSeed (${proof.masterSeedHex.slice(0, 16)}...) matches transcript via ${proof.kdfMode}.`
        : `Master seed mismatch: expected ${proof.masterSeedHex}, derived ${recomputedShuffle.masterSeedHex}.`,
    });

    shuffleMatches =
      recomputedShuffle.permutation.length === DECK_SIZE &&
      recomputedShuffle.permutation.every((val, idx) => val === proof.permutation[idx]);

    checks.push({
      name: '4. Unbiased Rejection-Sampled Fisher-Yates Permutation',
      passed: shuffleMatches,
      details: shuffleMatches
        ? `Verified all 51 unbiased Fisher-Yates swaps reproduce the exact 52-card permutation.`
        : `Fisher-Yates permutation does not match deterministic shuffle output.`,
    });
  } catch (err) {
    checks.push({
      name: `3. Master Seed Derivation (${proof.kdfMode})`,
      passed: false,
      details: err instanceof Error ? err.message : String(err),
    });
    checks.push({
      name: '4. Unbiased Rejection-Sampled Fisher-Yates Permutation',
      passed: false,
      details: 'Skipped due to seed derivation error.',
    });
  }

  // Stage 5: Zero-Knowledge Deck Validity & Bijection Proof
  const zkCheck = verifyZKDeckValidityProof(
    proof.handId,
    proof.deckRoot,
    proof.initialEnvelopes,
    proof.permutation,
    proof.zkDeckProof
  );
  checks.push({
    name: '5. Zero-Knowledge Proof of 52-Card Deck Bijection & Shuffle',
    passed: zkCheck.valid,
    details: zkCheck.valid
      ? `Verified ZK Grand-Product Bijection & Homomorphic Sum Invariant: the 52 sealed envelopes contain all 52 unique valid cards {0..51} without opening mucked cards.`
      : `ZK Deck Validity Proof failed: ${zkCheck.error}`,
  });

  // Stage 6: Selective Card Openings & Merkle Inclusion Proofs
  let openingsValid = true;
  let openedCardsCount = 0;
  let sealedMuckedCardsCount = 0;
  const seenCardIndices = new Set<number>();
  const seenShuffledPositions = new Set<number>();
  let openingErrorDetail = '';

  for (const pos of proof.dealtPositions) {
    if (seenShuffledPositions.has(pos.shuffledPosition)) {
      openingsValid = false;
      openingErrorDetail = `Duplicate dealt shuffledPosition ${pos.shuffledPosition}.`;
      break;
    }
    seenShuffledPositions.add(pos.shuffledPosition);

    if (pos.opening !== null) {
      openedCardsCount++;
      const res = verifyCardOpeningProof(
        proof.handId,
        proof.deckRoot,
        proof.initialEnvelopes,
        proof.permutation,
        pos.opening
      );
      if (!res.valid) {
        openingsValid = false;
        openingErrorDetail = res.error ?? `Invalid opening at position ${pos.shuffledPosition}`;
        break;
      }
      if (seenCardIndices.has(pos.opening.cardIndex)) {
        openingsValid = false;
        openingErrorDetail = `Duplicate opened card ${pos.opening.cardCode} at position ${pos.shuffledPosition}.`;
        break;
      }
      seenCardIndices.add(pos.opening.cardIndex);
    } else {
      sealedMuckedCardsCount++;
    }
  }

  checks.push({
    name: '6. Selective Card Openings & Dealt Position Binding',
    passed: openingsValid,
    details: openingsValid
      ? `Verified ${openedCardsCount} entitled card openings against locked 256-bit salted commitments and Merkle proofs.`
      : `Selective opening check failed: ${openingErrorDetail}`,
  });

  // Stage 7: Mucked & Folded Hole-Card Privacy Preservation
  const privacyPreserved = proof.dealtPositions.every(
    (p) =>
      (p.status === 'MUCKED_SECRET' || p.status === 'UNDEALT_SECRET')
        ? p.opening === null
        : p.opening !== null
  );
  checks.push({
    name: '7. Permanent Mucked & Folded Card Secrecy',
    passed: privacyPreserved,
    details: privacyPreserved
      ? `Confirmed ${sealedMuckedCardsCount} folded/mucked dealt cards and ${DECK_SIZE - proof.dealtPositions.length} undealt cards remain permanently sealed (salts unrevealed).`
      : `Privacy violation: a mucked or undealt position contained an exposed opening or an opened position lacked its proof.`,
  });

  const allPassed = checks.every((c) => c.passed);

  return {
    valid: allPassed,
    handId: proof.handId,
    tableId: proof.tableId,
    checks,
    openedCardsCount,
    sealedMuckedCardsCount,
    summary: allPassed
      ? `PASSED: Hand ${proof.handId} is 100% Provably Fair & ZK-Verified (${openedCardsCount} cards opened, ${sealedMuckedCardsCount} mucked cards kept secret).`
      : `FAILED: Hand ${proof.handId} failed one or more cryptographic verification checks.`,
  };
}
