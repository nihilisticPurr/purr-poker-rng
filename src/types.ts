/**
 * @purr-poker/rng - Core Types & Canonical Card Representation
 * Compatible with HyperPokerServer (purr-poker-server) DeckService & Game types.
 */

export const CardSuit = {
  CLUBS: 'c',
  DIAMONDS: 'd',
  HEARTS: 'h',
  SPADES: 's',
} as const;
export type CardSuit = (typeof CardSuit)[keyof typeof CardSuit];

export const CardRank = {
  TWO: '2',
  THREE: '3',
  FOUR: '4',
  FIVE: '5',
  SIX: '6',
  SEVEN: '7',
  EIGHT: '8',
  NINE: '9',
  TEN: 'T',
  JACK: 'J',
  QUEEN: 'Q',
  KING: 'K',
  ACE: 'A',
} as const;
export type CardRank = (typeof CardRank)[keyof typeof CardRank];

export interface Card {
  suit: CardSuit;
  rank: CardRank;
  code: string;
  suitDisplay?: string;
  rankDisplay?: string;
}

export const SUIT_ORDER: readonly CardSuit[] = [
  CardSuit.CLUBS,
  CardSuit.DIAMONDS,
  CardSuit.HEARTS,
  CardSuit.SPADES,
] as const;

export const RANK_ORDER: readonly CardRank[] = [
  CardRank.TWO,
  CardRank.THREE,
  CardRank.FOUR,
  CardRank.FIVE,
  CardRank.SIX,
  CardRank.SEVEN,
  CardRank.EIGHT,
  CardRank.NINE,
  CardRank.TEN,
  CardRank.JACK,
  CardRank.QUEEN,
  CardRank.KING,
  CardRank.ACE,
] as const;

export const SUIT_SYMBOLS: Record<CardSuit, string> = {
  [CardSuit.CLUBS]: '♣',
  [CardSuit.DIAMONDS]: '♦',
  [CardSuit.HEARTS]: '♥',
  [CardSuit.SPADES]: '♠',
};

export const DECK_SIZE = 52;

/**
 * Supported Key Derivation Functions for Master Shuffle Seed derivation
 */
export type KdfMode = 'SHAKE256' | 'HKDF-SHA256';

/**
 * Stage at which a card is dealt or revealed
 */
export type DealStage =
  | 'HOLE_CARD'
  | 'BURN'
  | 'FLOP'
  | 'TURN'
  | 'RIVER'
  | 'SHOWDOWN';

/**
 * Publicly visible sealed card envelope (published BEFORE shuffle entropy is revealed)
 */
export interface SealedCardEnvelope {
  /** Position in the initial pre-shuffled commitment array (0..51) */
  envelopeIndex: number;
  /** SHA-256 salted commitment: SHA256("PURR_CARD_V1" || handId || envelopeIndex || cardIndex || salt256) */
  commitment: string;
  /** Algebraic Pedersen commitment g^(cardIndex + 1) * h^blinding mod P for Zero-Knowledge bijection proof */
  zkCommitment: string;
}

/**
 * Server-side secret record for an individual card envelope.
 * Never exported for folded or mucked hole cards.
 */
export interface SecretCardRecord extends SealedCardEnvelope {
  /** Canonical integer representation of the card (0..51) */
  cardIndex: number;
  /** Short card code (e.g. "Ah", "Ks", "2c") */
  cardCode: string;
  /** Full Card object compatible with HyperPokerServer */
  card: Card;
  /** 256-bit (32-byte) CSPRNG secret salt encoded as 64-char hex */
  saltHex: string;
}

/**
 * Phase 1: Participant's pre-commitment to a 256-bit entropy seed
 */
export interface EntropyCommitment {
  participantId: string;
  role: 'server' | 'player';
  seatIndex?: number;
  /** SHA-256("PURR_ENTROPY_V1" || handId || participantId || entropyBytes) */
  commitmentHash: string;
  committedAt: number;
}

/**
 * Phase 2: Participant's revealed 256-bit entropy seed after all commitments are locked
 */
export interface EntropyReveal {
  participantId: string;
  role: 'server' | 'player';
  seatIndex?: number;
  /** 64-character hex string (256 bits) */
  entropyHex: string;
  revealedAt: number;
}

/**
 * Audit trace of a single step in the unbiased Fisher-Yates shuffle
 */
export interface FisherYatesStep {
  /** Swap index i from 51 down to 1 */
  i: number;
  /** Unbiased target swap index j in [0, i] */
  j: number;
  /** Accepted 32-bit unsigned integer drawn from the deterministic XOF/KDF stream */
  randomUint32: number;
  /** Largest multiple of (i + 1) <= 2^32 used for rejection sampling */
  rejectionLimit: number;
  /** Number of 32-bit words consumed (1 unless rejection sampling triggered) */
  attempts: number;
}

/**
 * Full deterministic shuffle output
 */
export interface ShuffleResult {
  /** Permutation array of length 52: permutation[dealtPos] = initialEnvelopeIndex */
  permutation: number[];
  /** Commitments rearranged according to permutation */
  shuffledCommitments: string[];
  /** ZK Pedersen commitments rearranged according to permutation */
  shuffledZkCommitments: string[];
  /** Step-by-step audit trace of Fisher-Yates swaps */
  steps: FisherYatesStep[];
  /** Derived 256-bit master seed (hex) */
  masterSeedHex: string;
  /** KDF algorithm used ('SHAKE256' or 'HKDF-SHA256') */
  kdfMode: KdfMode;
}

/**
 * Selective opening proof for a single card that a player (or the public) is entitled to see.
 * Mucked/folded cards NEVER generate a public CardOpeningProof.
 */
export interface CardOpeningProof {
  /** Final position in the shuffled deck (0..51) */
  shuffledPosition: number;
  /** Original pre-shuffle envelope index: permutation[shuffledPosition] */
  initialEnvelopeIndex: number;
  /** Canonical card index (0..51) */
  cardIndex: number;
  /** Card code (e.g., "As", "Td") */
  cardCode: string;
  /** HyperPokerServer-compatible Card object */
  card: Card;
  /** 256-bit secret salt for this specific envelope ONLY */
  saltHex: string;
  /** SHA-256 commitment matching initialEnvelopes[initialEnvelopeIndex].commitment */
  commitment: string;
  /** ZK commitment matching initialEnvelopes[initialEnvelopeIndex].zkCommitment */
  zkCommitment: string;
  /** Merkle inclusion path proving commitment belongs to deckRoot at initialEnvelopeIndex */
  merkleProof: string[];
  /** Who is entitled to this opening ('public' or specific playerId/seat) */
  recipient: 'public' | string;
  /** Deal stage */
  stage: DealStage;
  /** Optional seat index for player hole cards */
  seatIndex?: number;
}

/**
 * Zero-Knowledge Proof of Deck Validity & Shuffle Permutation
 * Proves without revealing any card values or salts that:
 * 1. The 52 initial envelopes contain an exact bijection (permutation) of the 52 canonical cards {0..51}.
 * 2. Each card commitment is bound to its algebraic commitment via Schnorr/Sigma range & polynomial roots.
 * 3. The shuffled deck is the exact permutation pi of the committed deck.
 * Optionally includes a compiled Circom Groth16 BN254 zk-SNARK proof when snarkjs artifacts are loaded.
 */
export interface ZKDeckValidityProof {
  protocol: 'PURR-ZK-DECK-V1';
  /** Fiat-Shamir polynomial root challenge gamma derived from transcript + all 52 commitments */
  fiatShamirChallengeHex: string;
  /**
   * Shuffled blinded polynomial factors and Schnorr Knowledge-of-Exponent responses
   * proving prod_{i=0}^{51} (gamma - card_i) == prod_{k=0}^{51} (gamma - k) in F_q
   * without leaking which envelope holds which card.
   */
  grandProductCommitment: string;
  /** Aggregate blinding proof response verifying homomorphic sum & product invariants */
  aggregateBlindingResponseHex: string;
  /** Sum of committed card indices commitment g^(sum c_i) h^(sum r_i) where sum c_i = 1326 */
  sumInvariantProof: {
    expectedCardIndexSum: number; // Always 0 + 1 + ... + 51 = 1326
    aggregateCommitment: string;
    schnorrChallengeHex: string;
    schnorrResponseBlindingHex: string;
  };
  /** Pairwise distinctness & valid range [0, 51] per-envelope Sigma proof commitments */
   factorCommitments: Array<{
    shuffledRankOrderCommitment: string;
    blindingProofChallenge: string;
    blindingProofResponseSValue: string;
    blindingProofResponseSBlinding: string;
  }>;
  /** Permutation commitment hash binding shuffledZkCommitments[j] === initialEnvelopes[permutation[j]].zkCommitment */
  permutationTranscriptHash: string;
  /** Optional Groth16 zk-SNARK proof object (from circuits/deck_shuffle.circom) */
  groth16Proof?: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: 'groth16';
    curve: 'bn128';
    publicSignals: string[];
  };
}

/**
 * Metadata for each dealt position in the hand (whether opened or permanently mucked/secret)
 */
export interface DealtPositionSummary {
  shuffledPosition: number;
  initialEnvelopeIndex: number;
  stage: DealStage;
  seatIndex?: number;
  playerId?: string;
  status: 'OPENED_PUBLIC' | 'OPENED_PRIVATE' | 'MUCKED_SECRET' | 'UNDEALT_SECRET';
  /** Present ONLY if status is OPENED_PUBLIC (or OPENED_PRIVATE for the requesting player's own view) */
  opening: CardOpeningProof | null;
}

/**
 * Complete Provably Fair + ZK Hand Proof Package
 * Can be verified offline by any player using the CLI or Web Verifier.
 */
export interface PublicHandProof {
  version: '1.0.0';
  handId: string;
  tableId: string;
  timestamp: string;
  kdfMode: KdfMode;
  /** Merkle root of the 52 initial sealed card envelopes (locked before entropy reveal) */
  deckRoot: string;
  /** 52 initial sealed envelopes (card values and salts hidden) */
  initialEnvelopes: SealedCardEnvelope[];
  /** Pre-locked entropy commitments from server and all seated players */
  entropyCommitments: EntropyCommitment[];
  /** Revealed entropy seeds after commitment lock */
  entropyReveals: EntropyReveal[];
  /** Derived 256-bit master shuffle seed */
  masterSeedHex: string;
  /** Deterministic unbiased Fisher-Yates permutation (length 52) */
  permutation: number[];
  /** Zero-Knowledge proof that the 52 sealed envelopes contain all 52 unique valid cards */
  zkDeckProof: ZKDeckValidityProof;
  /** Dealt positions with selective card openings (mucked/folded cards have opening: null) */
  dealtPositions: DealtPositionSummary[];
}

/**
 * Detailed verification result returned by the verifier
 */
export interface VerificationCheck {
  name: string;
  passed: boolean;
  details: string;
}

export interface VerificationReport {
  valid: boolean;
  handId: string;
  tableId: string;
  checks: VerificationCheck[];
  openedCardsCount: number;
  sealedMuckedCardsCount: number;
  summary: string;
}
