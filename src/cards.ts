/**
 * @purr-poker/rng - Canonical 52-Card Deck Utilities
 * Matches HyperPokerServer's DeckService ordering:
 * Suits: Clubs ('c'), Diamonds ('d'), Hearts ('h'), Spades ('s')
 * Ranks: '2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'
 */

import crypto from 'node:crypto';
import {
  type Card,
  CardRank,
  CardSuit,
  DECK_SIZE,
  RANK_ORDER,
  SUIT_ORDER,
  SUIT_SYMBOLS,
} from './types.ts';

/**
 * Convert a canonical card index (0..51) to a Card object
 */
export function indexToCard(cardIndex: number): Card {
  if (!Number.isInteger(cardIndex) || cardIndex < 0 || cardIndex >= DECK_SIZE) {
    throw new RangeError(`Invalid canonical cardIndex: ${cardIndex}. Must be an integer in [0, 51].`);
  }
  const suitIndex = Math.floor(cardIndex / 13);
  const rankIndex = cardIndex % 13;
  const suit = SUIT_ORDER[suitIndex];
  const rank = RANK_ORDER[rankIndex];

  return {
    suit,
    rank,
    code: `${rank}${suit}`,
    suitDisplay: SUIT_SYMBOLS[suit],
    rankDisplay: rank === CardRank.TEN ? '10' : rank,
  };
}

/**
 * Convert a Card or 2-character code (e.g. "Ah", "2c") to its canonical index (0..51)
 */
export function cardToIndex(cardOrCode: Card | string): number {
  const code = typeof cardOrCode === 'string' ? cardOrCode : `${cardOrCode.rank}${cardOrCode.suit}`;
  if (code.length !== 2) {
    throw new Error(`Invalid card code "${code}". Expected 2-char code like "Ah" or "2c".`);
  }
  const rankChar = code[0] as CardRank;
  const suitChar = code[1].toLowerCase() as CardSuit;

  const suitIndex = SUIT_ORDER.indexOf(suitChar);
  const rankIndex = RANK_ORDER.indexOf(rankChar);

  if (suitIndex === -1 || rankIndex === -1) {
    throw new Error(`Invalid card code "${code}". Unrecognized rank or suit.`);
  }

  return suitIndex * 13 + rankIndex;
}

/**
 * Create the canonical ordered 52-card deck (indices 0..51)
 */
export function createCanonicalDeck(): Card[] {
  const deck: Card[] = [];
  for (let i = 0; i < DECK_SIZE; i++) {
    deck.push(indexToCard(i));
  }
  return deck;
}

/**
 * Generate a server-side random initial permutation of [0..51] using Node CSPRNG
 * BEFORE committing the 52 sealed envelopes.
 *
 * Why pre-permute the initial envelopes?
 * Because even when players know the public Fisher-Yates permutation pi,
 * pre-permuting the initial committed envelopes ensures that knowing which initial
 * envelope index pi[j] landed in a mucked seat reveals ZERO information about the
 * card inside (every initial envelope is equally likely to hold any of the 52 cards,
 * hidden behind a 256-bit salt, while the ZK proof proves the 52 envelopes form a valid deck).
 */
export function generateSecretInitialDeckOrder(): number[] {
  const indices = Array.from({ length: DECK_SIZE }, (_, i) => i);
  for (let i = DECK_SIZE - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  return indices;
}
