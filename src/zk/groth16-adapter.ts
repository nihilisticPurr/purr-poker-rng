/**
 * @purr-poker/rng - Circom 2.1 Groth16 / PLONK Witness Builder & SnarkJS Bridge
 *
 * Bridges the TypeScript SDK with `circuits/deck_shuffle.circom` when compiled
 * WASM and ZKey artifacts are provided for succinct BN254 zk-SNARK proofs.
 */

import { DECK_SIZE, type SecretCardRecord } from '../types.ts';

export const BN254_SCALAR_FIELD = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

export interface CircomDeckShuffleInput {
  initialCommitments: string[];
  shuffledCommitments: string[];
  permutation: string[];
  fiatShamirChallenge: string;
  cards: string[];
  salts: string[];
}

/**
 * Compute the circuit-compatible algebraic commitment in BN254 F_r matching CommitmentHasher()
 * in `circuits/deck_shuffle.circom`.
 */
export function computeCircuitFieldCommitment(
  cardIndex: number,
  saltScalar: bigint,
  envelopeIndex: number
): bigint {
  const s = ((saltScalar % BN254_SCALAR_FIELD) + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD;
  const saltSq = (s * s) % BN254_SCALAR_FIELD;
  const mix =
    (s * BigInt(envelopeIndex + 101) + BigInt(cardIndex + 1)) % BN254_SCALAR_FIELD;
  return (saltSq + mix) % BN254_SCALAR_FIELD;
}

/**
 * Build the exact witness input JSON for `circuits/deck_shuffle.circom`
 */
export function buildCircomDeckShuffleWitnessInput(
  secretRecords: SecretCardRecord[],
  permutation: number[],
  fiatShamirChallengeHex: string
): CircomDeckShuffleInput {
  if (secretRecords.length !== DECK_SIZE || permutation.length !== DECK_SIZE) {
    throw new Error(`Expected ${DECK_SIZE} records and permutation entries.`);
  }

  const cards: string[] = [];
  const salts: string[] = [];
  const initialCommitments: string[] = [];

  for (let i = 0; i < DECK_SIZE; i++) {
    const rec = secretRecords[i];
    const saltScalar = BigInt('0x' + rec.saltHex) % BN254_SCALAR_FIELD;
    const com = computeCircuitFieldCommitment(rec.cardIndex, saltScalar, i);

    cards.push(String(rec.cardIndex));
    salts.push(saltScalar.toString(10));
    initialCommitments.push(com.toString(10));
  }

  const shuffledCommitments = permutation.map((envIdx) => initialCommitments[envIdx]);
  const challengeScalar = BigInt('0x' + fiatShamirChallengeHex) % BN254_SCALAR_FIELD;

  return {
    initialCommitments,
    shuffledCommitments,
    permutation: permutation.map(String),
    fiatShamirChallenge: challengeScalar.toString(10),
    cards,
    salts,
  };
}
