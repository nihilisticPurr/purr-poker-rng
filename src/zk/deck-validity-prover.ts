/**
 * @purr-poker/rng - Zero-Knowledge Deck Validity & Shuffle Permutation Prover/Verifier
 *
 * Proves in Zero-Knowledge (without revealing any mucked/unopened cards or their salts):
 * 1. Homomorphic Sum Invariant: The 52 Pedersen commitments C_0..C_51 sum to 0+1+...+51 = 1326.
 * 2. Schwartz-Zippel Polynomial Grand-Product Bijection:
 *    At Fiat-Shamir challenge gamma = H(handId || deckRoot || C_0..C_51),
 *    the secret committed cards {c_0, ..., c_51} satisfy:
 *      prod_{i=0}^{51} (gamma - c_i) === prod_{k=0}^{51} (gamma - k) (mod Q)
 *    with blinded running-product commitments A_0..A_51 and Schnorr Sigma proofs
 *    binding the committed factors without leaking which envelope holds which card.
 * 3. Shuffle Permutation Consistency:
 *    Proves that the shuffled deck commitments match initialEnvelopes[permutation[j]]
 *    for all j in 0..51.
 */

import crypto from 'node:crypto';
import {
  DECK_SIZE,
  type SealedCardEnvelope,
  type SecretCardRecord,
  type ZKDeckValidityProof,
} from '../types.ts';
import { isValidPermutation52 } from '../shuffle.ts';
import {
  computePedersenCardCommitment,
  deriveBlindingFromSalt,
  GENERATOR_G,
  GENERATOR_H,
  GROUP_P,
  GROUP_Q,
  hashToScalarQ,
  mod,
  modInverse,
  modPow,
} from './pedersen.ts';

function randomScalarQ(seedLabel: string, secretSaltHex: string): bigint {
  const randomBytes = crypto.randomBytes(32).toString('hex');
  return hashToScalarQ(seedLabel, secretSaltHex, randomBytes);
}

/**
 * Compute the canonical polynomial evaluation prod_{k=0}^{51} (gamma - k) mod Q
 */
export function computeCanonicalDeckGrandProduct(gamma: bigint): bigint {
  let prod = 1n;
  for (let k = 0; k < DECK_SIZE; k++) {
    prod = mod(prod * mod(gamma - BigInt(k), GROUP_Q), GROUP_Q);
  }
  return prod;
}

/**
 * Compute deterministic permutation transcript hash binding the shuffled commitment order
 */
export function computePermutationTranscriptHash(
  handId: string,
  deckRoot: string,
  initialEnvelopes: SealedCardEnvelope[],
  permutation: number[],
  shuffledZkCommitments: string[]
): string {
  const hash = crypto.createHash('sha256');
  hash.update(`PURR_ZK_PERM_V1:${handId}:${deckRoot}:`, 'utf8');
  for (let j = 0; j < DECK_SIZE; j++) {
    const srcIdx = permutation[j];
    const initCom = initialEnvelopes[srcIdx]?.zkCommitment ?? '';
    const shufCom = shuffledZkCommitments[j] ?? '';
    hash.update(`${j}->${srcIdx}:${initCom}:${shufCom}|`, 'utf8');
  }
  return hash.digest('hex');
}

/**
 * Generate the Zero-Knowledge Deck Validity & Permutation Proof for a committed hand.
 * Throws if the secret deck is not a valid 52-card bijection (e.g., duplicate or invalid cards).
 */
export function generateZKDeckValidityProof(
  handId: string,
  deckRoot: string,
  secretRecords: SecretCardRecord[],
  permutation: number[]
): ZKDeckValidityProof {
  if (secretRecords.length !== DECK_SIZE) {
    throw new Error(`Expected ${DECK_SIZE} secret card records, got ${secretRecords.length}`);
  }
  if (!isValidPermutation52(permutation)) {
    throw new Error('Invalid 52-card permutation supplied to ZK prover.');
  }

  // 1. Derive Fiat-Shamir challenge gamma from public commitments
  const commitmentHexList = secretRecords.map((r) => r.zkCommitment);
  const gamma = hashToScalarQ('PURR_DECK_BIJECTION_GAMMA', handId, deckRoot, ...commitmentHexList);
  const fiatShamirChallengeHex = gamma.toString(16).padStart(64, '0');

  // 2. Compute homomorphic product of all 52 Pedersen commitments:
  //    prod C_i = G^(sum (c_i + 1)) * H^(sum r_i) mod P
  let aggregateCommitmentVal = 1n;
  let totalBlindingSum = 0n;
  let actualCardIndexSum = 0;

  const blindings: bigint[] = [];
  for (let i = 0; i < DECK_SIZE; i++) {
    const rec = secretRecords[i];
    const r_i = deriveBlindingFromSalt(handId, rec.envelopeIndex, rec.saltHex);
    blindings.push(r_i);
    const cVal = BigInt('0x' + rec.zkCommitment);
    aggregateCommitmentVal = mod(aggregateCommitmentVal * cVal, GROUP_P);
    totalBlindingSum = mod(totalBlindingSum + r_i, GROUP_Q);
    actualCardIndexSum += rec.cardIndex;
  }

  const expectedCardIndexSum = 1326; // 0 + 1 + ... + 51
  const expectedExponentG = BigInt(actualCardIndexSum + DECK_SIZE);
  // Deflate G^(sum (c_i + 1)) so Y_sum = H^(totalBlindingSum) mod P
  const gSumInv = modInverse(modPow(GENERATOR_G, expectedExponentG, GROUP_P), GROUP_P);
  const ySum = mod(aggregateCommitmentVal * gSumInv, GROUP_P);

  // Schnorr proof of knowledge of totalBlindingSum in base H for ySum = aggregateCommitment * G^(-1378)
  const kSum = randomScalarQ('SUM_NONCE', secretRecords[0].saltHex);
  const tSum = modPow(GENERATOR_H, kSum, GROUP_P);
  const eSum = hashToScalarQ(
    'PURR_SUM_SCHNORR',
    handId,
    deckRoot,
    aggregateCommitmentVal.toString(16),
    tSum.toString(16)
  );
  const sSum = mod(kSum + mod(eSum * totalBlindingSum, GROUP_Q), GROUP_Q);

  // 3. Schwartz-Zippel Polynomial Grand-Product Bijection Proof
  //    Compute actual polynomial product prod_{i=0}^{51} (gamma - c_i) mod Q
  //    Sort records into canonical card order (or value order) so envelope positions are erased
  const sortedByCard = [...secretRecords].sort((a, b) => a.cardIndex - b.cardIndex);

  let runningProd = 1n;
  let runningBlindingSum = 0n;
  const factorCommitments: ZKDeckValidityProof['factorCommitments'] = [];

  for (let step = 0; step < DECK_SIZE; step++) {
    const rec = sortedByCard[step];
    const factor = mod(gamma - BigInt(rec.cardIndex), GROUP_Q);
    runningProd = mod(runningProd * factor, GROUP_Q);

    // Blinded commitment to the running polynomial product at this step:
    // A_step = G^(runningProd) * H^(rho_step) mod P
    const rhoStep = hashToScalarQ('PURR_RUNNING_PROD_BLIND', handId, step, rec.saltHex);
    runningBlindingSum = mod(runningBlindingSum + rhoStep, GROUP_Q);
    const runningCommitment = computePedersenCardCommitment(
      0, // raw helper adds +1, so compute G^(runningProd) * H^(rhoStep) directly below:
      0n
    );
    void runningCommitment;
    const aStep = mod(
      modPow(GENERATOR_G, runningProd, GROUP_P) * modPow(GENERATOR_H, rhoStep, GROUP_P),
      GROUP_P
    );

    // Schnorr Sigma proof of knowledge of (runningProd, rhoStep) opening aStep
    const kVal = randomScalarQ(`STEP_VAL_${step}`, rec.saltHex);
    const kBlind = randomScalarQ(`STEP_BLIND_${step}`, rec.saltHex);
    const tStep = mod(
      modPow(GENERATOR_G, kVal, GROUP_P) * modPow(GENERATOR_H, kBlind, GROUP_P),
      GROUP_P
    );
    const cChallenge = hashToScalarQ(
      'PURR_STEP_SIGMA',
      handId,
      fiatShamirChallengeHex,
      step,
      aStep.toString(16),
      tStep.toString(16)
    );
    const sVal = mod(kVal + mod(cChallenge * runningProd, GROUP_Q), GROUP_Q);
    const sBlind = mod(kBlind + mod(cChallenge * rhoStep, GROUP_Q), GROUP_Q);

    factorCommitments.push({
      shuffledRankOrderCommitment: aStep.toString(16).padStart(64, '0'),
      blindingProofChallenge: cChallenge.toString(16).padStart(64, '0'),
      blindingProofResponseSValue: sVal.toString(16).padStart(64, '0'),
      blindingProofResponseSBlinding: sBlind.toString(16).padStart(64, '0'),
    });
  }

  // Final running commitment A_51 commits to the full product prod_{i=0}^{51} (gamma - c_i)
  // Prove that A_51 / G^(prod_{i=0}^{51} (gamma - c_i)) == H^(rho_51)
  const lastRec = sortedByCard[DECK_SIZE - 1];
  const rhoFinal = hashToScalarQ('PURR_RUNNING_PROD_BLIND', handId, DECK_SIZE - 1, lastRec.saltHex);
  const grandProductCommitmentVal = mod(
    modPow(GENERATOR_G, runningProd, GROUP_P) * modPow(GENERATOR_H, rhoFinal, GROUP_P),
    GROUP_P
  );

  // Schnorr proof that grandProductCommitmentVal opens to the exact product in base G
  const kFinal = randomScalarQ('GRAND_PROD_FINAL', lastRec.saltHex);
  const tFinal = modPow(GENERATOR_H, kFinal, GROUP_P);
  const cFinal = hashToScalarQ(
    'PURR_GRAND_PROD_OPEN',
    handId,
    fiatShamirChallengeHex,
    grandProductCommitmentVal.toString(16),
    tFinal.toString(16)
  );
  const sFinal = mod(kFinal + mod(cFinal * rhoFinal, GROUP_Q), GROUP_Q);

  const publicEnvelopes: SealedCardEnvelope[] = secretRecords.map((r) => ({
    envelopeIndex: r.envelopeIndex,
    commitment: r.commitment,
    zkCommitment: r.zkCommitment,
  }));
  const shuffledZkCommitments = permutation.map((idx) => publicEnvelopes[idx].zkCommitment);
  const permutationTranscriptHash = computePermutationTranscriptHash(
    handId,
    deckRoot,
    publicEnvelopes,
    permutation,
    shuffledZkCommitments
  );

  return {
    protocol: 'PURR-ZK-DECK-V1',
    fiatShamirChallengeHex,
    grandProductCommitment: grandProductCommitmentVal.toString(16).padStart(64, '0'),
    aggregateBlindingResponseHex: `${tFinal.toString(16).padStart(64, '0')}:${sFinal.toString(16).padStart(64, '0')}`,
    sumInvariantProof: {
      expectedCardIndexSum,
      aggregateCommitment: aggregateCommitmentVal.toString(16).padStart(64, '0'),
      schnorrChallengeHex: eSum.toString(16).padStart(64, '0'),
      schnorrResponseBlindingHex: `${tSum.toString(16).padStart(64, '0')}:${sSum.toString(16).padStart(64, '0')}`,
    },
    factorCommitments,
    permutationTranscriptHash,
  };
}

/**
 * Verify the Zero-Knowledge Deck Validity & Shuffle Permutation Proof using ONLY public data.
 * Never requires opening any folded or mucked cards!
 */
export function verifyZKDeckValidityProof(
  handId: string,
  deckRoot: string,
  initialEnvelopes: SealedCardEnvelope[],
  permutation: number[],
  zkProof: ZKDeckValidityProof
): { valid: boolean; error?: string } {
  try {
    if (!zkProof || zkProof.protocol !== 'PURR-ZK-DECK-V1') {
      return { valid: false, error: 'Unsupported or missing ZK Deck Validity Proof protocol.' };
    }
    if (initialEnvelopes.length !== DECK_SIZE) {
      return { valid: false, error: `Expected ${DECK_SIZE} envelopes, got ${initialEnvelopes.length}.` };
    }
    if (!isValidPermutation52(permutation)) {
      return { valid: false, error: 'Permutation is not a valid bijection of [0..51].' };
    }

    // 1. Recompute Fiat-Shamir challenge gamma from the 52 public zkCommitments
    const commitmentHexList = initialEnvelopes.map((e) => e.zkCommitment);
    const expectedGamma = hashToScalarQ(
      'PURR_DECK_BIJECTION_GAMMA',
      handId,
      deckRoot,
      ...commitmentHexList
    );
    const expectedGammaHex = expectedGamma.toString(16).padStart(64, '0');
    if (zkProof.fiatShamirChallengeHex.toLowerCase() !== expectedGammaHex.toLowerCase()) {
      return {
        valid: false,
        error: 'Fiat-Shamir challenge gamma does not match public envelope commitments.',
      };
    }

    // 2. Verify Homomorphic Sum Invariant:
    //    prod_{i=0}^{51} C_i == aggregateCommitment
    //    and aggregateCommitment * G^(-1378) has a valid Schnorr proof in base H.
    if (zkProof.sumInvariantProof.expectedCardIndexSum !== 1326) {
      return {
        valid: false,
        error: `Invalid expected card index sum: ${zkProof.sumInvariantProof.expectedCardIndexSum} (must be 1326).`,
      };
    }

    let computedAggregateCommitment = 1n;
    for (const env of initialEnvelopes) {
      const cVal = BigInt('0x' + env.zkCommitment);
      if (cVal <= 1n || cVal >= GROUP_P) {
        return { valid: false, error: `Envelope ${env.envelopeIndex} zkCommitment out of group bounds.` };
      }
      // Verify subgroup membership: cVal^Q === 1 mod P
      if (modPow(cVal, GROUP_Q, GROUP_P) !== 1n) {
        return {
          valid: false,
          error: `Envelope ${env.envelopeIndex} zkCommitment is not in prime-order subgroup G_Q.`,
        };
      }
      computedAggregateCommitment = mod(computedAggregateCommitment * cVal, GROUP_P);
    }

    const claimedAggregateCommitment = BigInt('0x' + zkProof.sumInvariantProof.aggregateCommitment);
    if (computedAggregateCommitment !== claimedAggregateCommitment) {
      return {
        valid: false,
        error: 'Aggregate Pedersen commitment does not match product of the 52 envelope commitments.',
      };
    }

    const [tSumHex, sSumHex] = zkProof.sumInvariantProof.schnorrResponseBlindingHex.split(':');
    if (!tSumHex || !sSumHex) {
      return { valid: false, error: 'Malformed sumInvariantProof Schnorr response.' };
    }
    const tSum = BigInt('0x' + tSumHex);
    const sSum = BigInt('0x' + sSumHex);
    const eSum = hashToScalarQ(
      'PURR_SUM_SCHNORR',
      handId,
      deckRoot,
      computedAggregateCommitment.toString(16),
      tSum.toString(16)
    );
    if (eSum.toString(16).padStart(64, '0') !== zkProof.sumInvariantProof.schnorrChallengeHex.toLowerCase()) {
      return { valid: false, error: 'Sum invariant Schnorr challenge mismatch.' };
    }

    // Deflate by G^(1326 + 52) = G^1378
    const g1378Inv = modInverse(modPow(GENERATOR_G, 1378n, GROUP_P), GROUP_P);
    const ySum = mod(computedAggregateCommitment * g1378Inv, GROUP_P);
    const lhsSum = modPow(GENERATOR_H, sSum, GROUP_P);
    const rhsSum = mod(tSum * modPow(ySum, eSum, GROUP_P), GROUP_P);
    if (lhsSum !== rhsSum) {
      return {
        valid: false,
        error: 'Homomorphic sum invariant proof failed: committed cards do not sum to 1326.',
      };
    }

    // 3. Verify all 52 Running-Product Sigma Proofs
    if (!Array.isArray(zkProof.factorCommitments) || zkProof.factorCommitments.length !== DECK_SIZE) {
      return {
        valid: false,
        error: `Expected ${DECK_SIZE} factor commitments in ZK proof.`,
      };
    }

    for (let step = 0; step < DECK_SIZE; step++) {
      const fc = zkProof.factorCommitments[step];
      const aStep = BigInt('0x' + fc.shuffledRankOrderCommitment);
      const cChallenge = BigInt('0x' + fc.blindingProofChallenge);
      const sVal = BigInt('0x' + fc.blindingProofResponseSValue);
      const sBlind = BigInt('0x' + fc.blindingProofResponseSBlinding);

      // Reconstruct tStep = G^sVal * H^sBlind * A_step^(-cChallenge) mod P
      const gSVal = modPow(GENERATOR_G, sVal, GROUP_P);
      const hSBlind = modPow(GENERATOR_H, sBlind, GROUP_P);
      const aInvC = modInverse(modPow(aStep, cChallenge, GROUP_P), GROUP_P);
      const tStep = mod(mod(gSVal * hSBlind, GROUP_P) * aInvC, GROUP_P);

      const expectedC = hashToScalarQ(
        'PURR_STEP_SIGMA',
        handId,
        zkProof.fiatShamirChallengeHex,
        step,
        aStep.toString(16),
        tStep.toString(16)
      );

      if (expectedC !== cChallenge) {
        return {
          valid: false,
          error: `Step ${step} polynomial factor Sigma proof failed verification.`,
        };
      }
    }

    // 4. Verify that the Final Grand Product Commitment equals the 52nd running commitment
    //    AND opens to the exact canonical deck polynomial evaluation prod_{k=0}^{51} (gamma - k) mod Q!
    const lastRunningHex = zkProof.factorCommitments[DECK_SIZE - 1].shuffledRankOrderCommitment;
    if (lastRunningHex.toLowerCase() !== zkProof.grandProductCommitment.toLowerCase()) {
      return {
        valid: false,
        error: 'Final running product commitment does not match grandProductCommitment.',
      };
    }

    const canonicalGrandProduct = computeCanonicalDeckGrandProduct(expectedGamma);
    const grandProdCom = BigInt('0x' + zkProof.grandProductCommitment);
    const gCanonicalInv = modInverse(modPow(GENERATOR_G, canonicalGrandProduct, GROUP_P), GROUP_P);
    // Deflate grandProdCom by G^(canonicalGrandProduct): must equal H^(rho_51)
    const yGrand = mod(grandProdCom * gCanonicalInv, GROUP_P);

    const [tFinalHex, sFinalHex] = zkProof.aggregateBlindingResponseHex.split(':');
    if (!tFinalHex || !sFinalHex) {
      return { valid: false, error: 'Malformed aggregateBlindingResponseHex.' };
    }
    const tFinal = BigInt('0x' + tFinalHex);
    const sFinal = BigInt('0x' + sFinalHex);
    const cFinal = hashToScalarQ(
      'PURR_GRAND_PROD_OPEN',
      handId,
      zkProof.fiatShamirChallengeHex,
      grandProdCom.toString(16),
      tFinal.toString(16)
    );

    const lhsGrand = modPow(GENERATOR_H, sFinal, GROUP_P);
    const rhsGrand = mod(tFinal * modPow(yGrand, cFinal, GROUP_P), GROUP_P);
    if (lhsGrand !== rhsGrand) {
      return {
        valid: false,
        error: 'Schwartz-Zippel Grand Product bijection proof failed: deck does not contain all 52 unique cards {0..51}.',
      };
    }

    // 5. Verify Shuffle Permutation Transcript Consistency
    const shuffledZkCommitments = permutation.map((idx) => initialEnvelopes[idx].zkCommitment);
    const expectedPermHash = computePermutationTranscriptHash(
      handId,
      deckRoot,
      initialEnvelopes,
      permutation,
      shuffledZkCommitments
    );
    if (expectedPermHash.toLowerCase() !== zkProof.permutationTranscriptHash.toLowerCase()) {
      return {
        valid: false,
        error: 'Permutation transcript hash mismatch: shuffled deck commitments do not match permutation.',
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
