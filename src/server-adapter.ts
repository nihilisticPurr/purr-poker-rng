/**
 * @purr-poker/rng - HyperPokerServer Integration Adapter (ProvablyFairHandSession)
 *
 * Stateful lifecycle manager for a single poker hand on HyperPokerServer:
 *   Phase 1 (Pre-Hand): Create 52 salted card envelopes + deckRoot + Server Entropy Commitment
 *   Phase 2 (Lock & Reveal): Lock player entropy commitments, reveal entropies, run unbiased
 *                            Fisher-Yates via SHAKE256/HKDF, and generate ZK Deck Bijection Proof
 *   Phase 3 (Gameplay): Issue selective card-opening proofs ONLY to entitled players
 *   Phase 4 (Post-Hand): Export PublicHandProof (mucked/folded hole cards permanently secret)
 */

import type {
  Card,
  CardOpeningProof,
  DealStage,
  DealtPositionSummary,
  EntropyCommitment,
  EntropyReveal,
  KdfMode,
  PublicHandProof,
  SealedCardEnvelope,
  SecretCardRecord,
  ShuffleResult,
  ZKDeckValidityProof,
} from './types.ts';
import { createCommittedDeck } from './commitments.ts';
import {
  createEntropyCommitment,
  generateEntropy256,
  verifyEntropyCommitmentsAndReveals,
} from './entropy.ts';
import { computeDeterministicShuffle } from './shuffle.ts';
import { generateZKDeckValidityProof } from './zk/deck-validity-prover.ts';
import { createCardOpeningProof } from './selective-opening.ts';

export interface HandSessionOptions {
  handId: string;
  tableId: string;
  kdfMode?: KdfMode;
  serverId?: string;
  serverEntropyHex?: string;
}

interface InternalDealtPosition {
  shuffledPosition: number;
  initialEnvelopeIndex: number;
  stage: DealStage;
  seatIndex?: number;
  playerId?: string;
  publiclyRevealed: boolean;
}

export class ProvablyFairHandSession {
  public readonly handId: string;
  public readonly tableId: string;
  public readonly kdfMode: KdfMode;
  public readonly serverId: string;
  public readonly deckRoot: string;
  public readonly publicEnvelopes: SealedCardEnvelope[];

  private readonly secretRecords: SecretCardRecord[];
  private readonly serverEntropyHex: string;
  private readonly entropyCommitments: EntropyCommitment[] = [];
  private readonly entropyReveals: EntropyReveal[] = [];
  private locked = false;
  private shuffleResult?: ShuffleResult;
  private zkDeckProof?: ZKDeckValidityProof;
  private nextDealCursor = 0;
  private readonly dealtPositions: InternalDealtPosition[] = [];

  constructor(options: HandSessionOptions) {
    this.handId = options.handId;
    this.tableId = options.tableId;
    this.kdfMode = options.kdfMode ?? 'SHAKE256';
    this.serverId = options.serverId ?? 'purrpoker-Dealer-v1';
    this.serverEntropyHex = options.serverEntropyHex ?? generateEntropy256();

    const committed = createCommittedDeck(this.handId);
    this.secretRecords = committed.secretRecords;
    this.publicEnvelopes = committed.publicEnvelopes;
    this.deckRoot = committed.deckRoot;

    // Server commits to its 256-bit entropy immediately at hand initialization
    const now = Date.now();
    this.entropyCommitments.push(
      createEntropyCommitment(
        this.handId,
        this.serverId,
        'server',
        this.serverEntropyHex,
        undefined,
        now
      )
    );
  }

  /**
   * Phase 1: Register a player's 256-bit entropy commitment before locking the hand
   */
  public addPlayerEntropyCommitment(commitment: EntropyCommitment): void {
    if (this.locked) {
      throw new Error('Cannot add entropy commitment after commitments are locked.');
    }
    if (this.entropyCommitments.some((c) => c.participantId === commitment.participantId)) {
      throw new Error(`Participant "${commitment.participantId}" has already committed entropy.`);
    }
    this.entropyCommitments.push(commitment);
  }

  /**
   * Convenience helper for committing & storing a player's 256-bit entropy seed
   */
  public commitAndQueuePlayerEntropy(
    playerId: string,
    seatIndex: number,
    entropyHex: string = generateEntropy256()
  ): { commitment: EntropyCommitment; entropyHex: string } {
    if (this.locked) {
      throw new Error('Cannot commit player entropy after commitments are locked.');
    }
    const now = Date.now();
    const commitment = createEntropyCommitment(
      this.handId,
      playerId,
      'player',
      entropyHex,
      seatIndex,
      now
    );
    this.addPlayerEntropyCommitment(commitment);
    this.entropyReveals.push({
      participantId: playerId,
      role: 'player',
      seatIndex,
      entropyHex,
      revealedAt: now + 1,
    });
    return { commitment, entropyHex };
  }

  /**
   * Phase 2: Lock all commitments, verify all revealed entropy seeds, derive the shuffle
   * via SHAKE256 / HKDF-SHA256 + unbiased Fisher-Yates, and generate the ZK Deck Proof.
   */
  public lockCommitmentsAndShuffle(additionalPlayerReveals: EntropyReveal[] = []): {
    shuffleResult: ShuffleResult;
    zkDeckProof: ZKDeckValidityProof;
  } {
    if (this.locked) {
      throw new Error('Hand commitments are already locked and shuffled.');
    }

    const now = Date.now() + 2;
    this.entropyReveals.push({
      participantId: this.serverId,
      role: 'server',
      entropyHex: this.serverEntropyHex,
      revealedAt: now,
    });

    for (const rev of additionalPlayerReveals) {
      if (!this.entropyReveals.some((r) => r.participantId === rev.participantId)) {
        this.entropyReveals.push(rev);
      }
    }

    const check = verifyEntropyCommitmentsAndReveals(
      this.handId,
      this.entropyCommitments,
      this.entropyReveals
    );
    if (!check.valid) {
      throw new Error(`Cannot lock hand: ${check.error}`);
    }

    this.locked = true;
    this.shuffleResult = computeDeterministicShuffle(
      this.handId,
      this.deckRoot,
      this.publicEnvelopes,
      this.entropyReveals,
      this.kdfMode
    );

    this.zkDeckProof = generateZKDeckValidityProof(
      this.handId,
      this.deckRoot,
      this.secretRecords,
      this.shuffleResult.permutation
    );

    return {
      shuffleResult: this.shuffleResult,
      zkDeckProof: this.zkDeckProof,
    };
  }

  /**
   * Deal 2 hole cards to each seated player (2 rounds of 1 card each, matching Texas Hold'em rules).
   * Returns each player's private cards and their private selective opening proofs.
   */
  public dealHoleCards(
    players: Array<{ seatIndex: number; playerId: string }>
  ): Record<
    string,
    {
      seatIndex: number;
      cards: Card[];
      privateOpenings: CardOpeningProof[];
    }
  > {
    this.ensureLocked();
    const result: Record<
      string,
      { seatIndex: number; cards: Card[]; privateOpenings: CardOpeningProof[] }
    > = {};

    for (const p of players) {
      result[p.playerId] = {
        seatIndex: p.seatIndex,
        cards: [],
        privateOpenings: [],
      };
    }

    // Round 1 & Round 2 hole card dealing
    for (let round = 0; round < 2; round++) {
      for (const p of players) {
        const pos = this.consumeNextPosition('HOLE_CARD', false, p.seatIndex, p.playerId);
        const opening = this.buildOpeningForPosition(pos, p.playerId);
        result[p.playerId].cards.push(opening.card);
        result[p.playerId].privateOpenings.push(opening);
      }
    }

    return result;
  }

  /**
   * Burn 1 card (kept permanently sealed in public proofs) and deal community cards
   */
  public dealCommunityStage(
    stage: 'FLOP' | 'TURN' | 'RIVER',
    burnCardFirst: boolean = true
  ): {
    cards: Card[];
    publicOpenings: CardOpeningProof[];
  } {
    this.ensureLocked();
    if (burnCardFirst) {
      this.consumeNextPosition('BURN', false);
    }

    const count = stage === 'FLOP' ? 3 : 1;
    const cards: Card[] = [];
    const publicOpenings: CardOpeningProof[] = [];

    for (let i = 0; i < count; i++) {
      const pos = this.consumeNextPosition(stage, true);
      const opening = this.buildOpeningForPosition(pos, 'public');
      cards.push(opening.card);
      publicOpenings.push(opening);
    }

    return { cards, publicOpenings };
  }

  /**
   * Reveal a player's hole cards at Showdown (only for non-mucked showdown hands).
   * Folded or mucked players never call this method, so their hole cards stay permanently secret.
   */
  public revealShowdownHand(playerId: string): CardOpeningProof[] {
    this.ensureLocked();
    const openings: CardOpeningProof[] = [];
    for (const pos of this.dealtPositions) {
      if (pos.stage === 'HOLE_CARD' && pos.playerId === playerId) {
        pos.publiclyRevealed = true;
        pos.stage = 'SHOWDOWN';
        openings.push(this.buildOpeningForPosition(pos, 'public'));
      }
    }
    return openings;
  }

  /**
   * Export the verifiable Hand Proof JSON.
   * - If `viewerPlayerId` is omitted, exports the Public Hand Proof (only community & showdown cards opened;
   *   all folded/mucked hole cards and burn cards have `opening: null` and their salts are NEVER included).
   * - If `viewerPlayerId` is provided, also includes that specific player's private hole-card openings
   *   so the player can verify their own folded hand while opponents' mucked hands remain sealed.
   */
  public exportHandProof(viewerPlayerId?: string): PublicHandProof {
    this.ensureLocked();
    const shuffle = this.shuffleResult!;
    const zkDeckProof = this.zkDeckProof!;

    const summaries: DealtPositionSummary[] = this.dealtPositions.map((pos) => {
      if (pos.publiclyRevealed) {
        return {
          shuffledPosition: pos.shuffledPosition,
          initialEnvelopeIndex: pos.initialEnvelopeIndex,
          stage: pos.stage,
          seatIndex: pos.seatIndex,
          playerId: pos.playerId,
          status: 'OPENED_PUBLIC',
          opening: this.buildOpeningForPosition(pos, 'public'),
        };
      }

      if (viewerPlayerId && pos.playerId === viewerPlayerId) {
        return {
          shuffledPosition: pos.shuffledPosition,
          initialEnvelopeIndex: pos.initialEnvelopeIndex,
          stage: pos.stage,
          seatIndex: pos.seatIndex,
          playerId: pos.playerId,
          status: 'OPENED_PRIVATE',
          opening: this.buildOpeningForPosition(pos, viewerPlayerId),
        };
      }

      return {
        shuffledPosition: pos.shuffledPosition,
        initialEnvelopeIndex: pos.initialEnvelopeIndex,
        stage: pos.stage,
        seatIndex: pos.seatIndex,
        playerId: pos.playerId,
        status: pos.stage === 'BURN' ? 'UNDEALT_SECRET' : 'MUCKED_SECRET',
        opening: null,
      };
    });

    return {
      version: '1.0.0',
      handId: this.handId,
      tableId: this.tableId,
      timestamp: new Date().toISOString(),
      kdfMode: this.kdfMode,
      deckRoot: this.deckRoot,
      initialEnvelopes: this.publicEnvelopes,
      entropyCommitments: [...this.entropyCommitments],
      entropyReveals: [...this.entropyReveals],
      masterSeedHex: shuffle.masterSeedHex,
      permutation: [...shuffle.permutation],
      zkDeckProof,
      dealtPositions: summaries,
    };
  }

  private ensureLocked(): void {
    if (!this.locked || !this.shuffleResult || !this.zkDeckProof) {
      throw new Error('Hand commitments must be locked and shuffled before dealing or exporting.');
    }
  }

  private consumeNextPosition(
    stage: DealStage,
    publiclyRevealed: boolean,
    seatIndex?: number,
    playerId?: string
  ): InternalDealtPosition {
    const shuffledPosition = this.nextDealCursor++;
    const initialEnvelopeIndex = this.shuffleResult!.permutation[shuffledPosition];
    const pos: InternalDealtPosition = {
      shuffledPosition,
      initialEnvelopeIndex,
      stage,
      seatIndex,
      playerId,
      publiclyRevealed,
    };
    this.dealtPositions.push(pos);
    return pos;
  }

  private buildOpeningForPosition(
    pos: InternalDealtPosition,
    recipient: 'public' | string
  ): CardOpeningProof {
    return createCardOpeningProof(
      this.handId,
      this.secretRecords,
      this.publicEnvelopes,
      this.shuffleResult!.permutation,
      pos.shuffledPosition,
      recipient,
      pos.stage,
      pos.seatIndex
    );
  }
}
