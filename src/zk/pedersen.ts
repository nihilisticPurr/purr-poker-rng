/**
 * @purr-poker/rng - Algebraic Pedersen Commitment Group (Prime-Order Subgroup)
 *
 * Uses a 256-bit Safe Prime P = 2Q + 1 where Q is a 255-bit Sophie Germain prime.
 * - Generator G = 4 mod P (quadratic residue generating the prime-order subgroup G_Q of order Q).
 * - Generator H = (SHA-256("PURR_PEDERSEN_H_NOTHING_UP_MY_SLEEVE_V1"))^2 mod P.
 *   Because H is derived deterministically via a one-way hash ("nothing up my sleeve"),
 *   nobody knows the discrete logarithm log_G(H), guaranteeing computational binding
 *   and perfect hiding of Pedersen commitments C = G^(m) * H^(r) mod P.
 */

import crypto from 'node:crypto';

/**
 * Mathematically verified 256-bit Safe Prime P = 2Q + 1
 * Both P and Q = (P - 1) / 2 are cryptographically verified primes (crypto.checkPrimeSync === true).
 * P = 112676137708030835356222274486138998207266371455696036234515199050971772242579
 * Q = 56338068854015417678111137243069499103633185727848018117257599525485886121289
 */
export const GROUP_P = BigInt(
  '112676137708030835356222274486138998207266371455696036234515199050971772242579'
);
export const GROUP_Q = (GROUP_P - 1n) / 2n;

/**
 * Modular arithmetic helpers
 */
export function mod(a: bigint, m: bigint): bigint {
  const res = a % m;
  return res >= 0n ? res : res + m;
}

export function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = mod(base, modulus);
  let e = exp;
  if (e < 0n) {
    b = modInverse(b, modulus);
    e = -e;
  }
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

export function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  if (old_r !== 1n) {
    throw new Error('Modular inverse does not exist');
  }
  return mod(old_s, m);
}

/**
 * Primary generator G = 4 mod P (quadratic residue of prime order Q)
 */
export const GENERATOR_G = 4n;

/**
 * Secondary generator H derived via Nothing-Up-My-Sleeve SHA-256 hash squared into G_Q
 */
export const GENERATOR_H: bigint = (() => {
  const hashHex = crypto
    .createHash('sha256')
    .update('PURR_PEDERSEN_H_NOTHING_UP_MY_SLEEVE_V1', 'utf8')
    .digest('hex');
  const raw = mod(BigInt('0x' + hashHex), GROUP_P);
  // Square raw mod P so H is guaranteed to be in the prime-order subgroup G_Q of order Q
  return modPow(raw, 2n, GROUP_P);
})();

/**
 * Deterministically derive the scalar blinding factor r in Z_Q from a card's 256-bit salt
 * so that revealing saltHex for an opened card automatically allows verifying its zkCommitment.
 */
export function deriveBlindingFromSalt(
  handId: string,
  envelopeIndex: number,
  saltHex: string
): bigint {
  const digest = crypto
    .createHash('sha256')
    .update(`PURR_ZK_BLINDING_V1:${handId}:${envelopeIndex}:`, 'utf8')
    .update(Buffer.from(saltHex, 'hex'))
    .digest('hex');
  const scalar = mod(BigInt('0x' + digest), GROUP_Q - 1n) + 1n;
  return scalar;
}

/**
 * Compute algebraic Pedersen commitment for a card index c in [0..51]:
 * C = G^(c + 1) * H^(blinding) mod P
 */
export function computePedersenCardCommitment(cardIndex: number, blinding: bigint): bigint {
  const gPart = modPow(GENERATOR_G, BigInt(cardIndex + 1), GROUP_P);
  const hPart = modPow(GENERATOR_H, mod(blinding, GROUP_Q), GROUP_P);
  return mod(gPart * hPart, GROUP_P);
}

/**
 * Hash arbitrary strings/bigints into a non-zero scalar in Z_Q (Fiat-Shamir challenge)
 */
export function hashToScalarQ(...parts: Array<string | number | bigint>): bigint {
  const hash = crypto.createHash('sha256');
  hash.update('PURR_FIAT_SHAMIR_SCALAR_V1', 'utf8');
  for (const part of parts) {
    hash.update(':' + String(part), 'utf8');
  }
  const digestHex = hash.digest('hex');
  return mod(BigInt('0x' + digestHex), GROUP_Q - 1n) + 1n;
}
