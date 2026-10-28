/**
 * @purr-poker/rng - Comprehensive Cryptographic & Protocol Test Suite
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCircomDeckShuffleWitnessInput,
  BN254_SCALAR_FIELD,
  cardToIndex,
  computeCardCommitment,
  computeCircuitFieldCommitment,
  computeDeckMerkleRoot,
  computeDeterministicShuffle,
  createCanonicalDeck,
  createCommittedDeck,
  createEntropyCommitment,
  DECK_SIZE,
  generateEntropy256,
  generateMerkleProof,
  generateZKDeckValidityProof,
  indexToCard,
  ProvablyFairHandSession,
  verifyEntropyCommitmentsAndReveals,
  verifyHandProof,
  verifyMerkleProof,
  verifyZKDeckValidityProof,
} from '../src/index.ts';

describe('@purr-poker/rng Provably Fair & Zero-Knowledge Protocol Suite', () => {
  it('1. Canonical 52-card deck bijection matches HyperPokerServer card codes', () => {
    const deck = createCanonicalDeck();
    assert.equal(deck.length, 52);

    const codes = new Set<string>();
    for (let i = 0; i < DECK_SIZE; i++) {
      const card = indexToCard(i);
      assert.equal(card.code, deck[i].code);
      assert.equal(cardToIndex(card), i);
      assert.equal(cardToIndex(card.code), i);
      codes.add(card.code);
    }
    assert.equal(codes.size, 52);
    assert.equal(indexToCard(0).code, '2c');
    assert.equal(indexToCard(51).code, 'As');
  });

  it('2. 52-card 256-bit salted commitments & Merkle inclusion proofs verify and detect tampering', () => {
    const handId = 'test_hand_merkle_01';
    const { secretRecords, publicEnvelopes, deckRoot } = createCommittedDeck(handId);

    assert.equal(secretRecords.length, 52);
    assert.equal(publicEnvelopes.length, 52);
    assert.equal(computeDeckMerkleRoot(publicEnvelopes), deckRoot);

    for (let i = 0; i < DECK_SIZE; i++) {
      const proof = generateMerkleProof(publicEnvelopes, i);
      assert.equal(proof.length, 6);
      assert.equal(verifyMerkleProof(publicEnvelopes[i], proof, deckRoot), true);

      // Tamper with commitment: Merkle proof must fail
      const tamperedEnvelope = {
        ...publicEnvelopes[i],
        commitment: computeCardCommitment(handId, i, (secretRecords[i].cardIndex + 1) % 52, secretRecords[i].saltHex),
      };
      assert.equal(verifyMerkleProof(tamperedEnvelope, proof, deckRoot), false);
    }
  });

  it('3. Multi-party 256-bit entropy commit-reveal locks before reveal and rejects tampered seeds', () => {
    const handId = 'test_hand_entropy_02';
    const serverSeed = generateEntropy256();
    const p1Seed = generateEntropy256();
    const p2Seed = generateEntropy256();

    const t0 = 1700000000000;
    const commitments = [
      createEntropyCommitment(handId, 'server', 'server', serverSeed, undefined, t0),
      createEntropyCommitment(handId, 'player_1', 'player', p1Seed, 0, t0 + 10),
      createEntropyCommitment(handId, 'player_2', 'player', p2Seed, 1, t0 + 20),
    ];

    const reveals = [
      { participantId: 'server', role: 'server' as const, entropyHex: serverSeed, revealedAt: t0 + 100 },
      { participantId: 'player_1', role: 'player' as const, seatIndex: 0, entropyHex: p1Seed, revealedAt: t0 + 110 },
      { participantId: 'player_2', role: 'player' as const, seatIndex: 1, entropyHex: p2Seed, revealedAt: t0 + 120 },
    ];

    const okResult = verifyEntropyCommitmentsAndReveals(handId, commitments, reveals);
    assert.equal(okResult.valid, true);

    // Tamper with server seed after commitment lock
    const badReveals = [
      { ...reveals[0], entropyHex: generateEntropy256() },
      reveals[1],
      reveals[2],
    ];
    const badResult = verifyEntropyCommitmentsAndReveals(handId, commitments, badReveals);
    assert.equal(badResult.valid, false);
    assert.match(badResult.error ?? '', /Entropy commitment mismatch/);
  });

  it('4. Deterministic Unbiased Fisher-Yates shuffle works with both SHAKE256 and HKDF-SHA256', () => {
    const handId = 'test_hand_kdf_03';
    const { publicEnvelopes, deckRoot } = createCommittedDeck(handId);
    const reveals = [
      { participantId: 'server', role: 'server' as const, entropyHex: generateEntropy256(), revealedAt: 200 },
      { participantId: 'alice', role: 'player' as const, seatIndex: 0, entropyHex: generateEntropy256(), revealedAt: 201 },
    ];

    const shake1 = computeDeterministicShuffle(handId, deckRoot, publicEnvelopes, reveals, 'SHAKE256');
    const shake2 = computeDeterministicShuffle(handId, deckRoot, publicEnvelopes, reveals, 'SHAKE256');
    assert.deepEqual(shake1.permutation, shake2.permutation);
    assert.equal(shake1.masterSeedHex, shake2.masterSeedHex);
    assert.equal(shake1.steps.length, 51);

    const hkdf1 = computeDeterministicShuffle(handId, deckRoot, publicEnvelopes, reveals, 'HKDF-SHA256');
    const hkdf2 = computeDeterministicShuffle(handId, deckRoot, publicEnvelopes, reveals, 'HKDF-SHA256');
    assert.deepEqual(hkdf1.permutation, hkdf2.permutation);
    assert.notEqual(shake1.masterSeedHex, hkdf1.masterSeedHex);
  });

  it('5. Heads-Up & Multi-Way Mucked Card Privacy: opponent never learns folded/mucked hole cards', () => {
    const session = new ProvablyFairHandSession({
      handId: 'test_hu_privacy_04',
      tableId: 'table_heads_up_1',
      kdfMode: 'SHAKE256',
    });

    session.commitAndQueuePlayerEntropy('Alice', 0);
    session.commitAndQueuePlayerEntropy('Bob', 1);
    session.lockCommitmentsAndShuffle();

    const dealt = session.dealHoleCards([
      { seatIndex: 0, playerId: 'Alice' },
      { seatIndex: 1, playerId: 'Bob' },
    ]);
    assert.equal(dealt.Alice.cards.length, 2);
    assert.equal(dealt.Bob.cards.length, 2);

    session.dealCommunityStage('FLOP', true);
    session.dealCommunityStage('TURN', true);
    session.dealCommunityStage('RIVER', true);

    // Suppose Bob folds on the River (or mucks at Showdown); only Alice shows her hand (or wins uncontested)
    // Export public proof: Bob's hole cards MUST have opening === null (256-bit salts withheld)
    const publicProof = session.exportHandProof();
    const bobPublicPositions = publicProof.dealtPositions.filter((p) => p.playerId === 'Bob');
    assert.equal(bobPublicPositions.length, 2);
    for (const pos of bobPublicPositions) {
      assert.equal(pos.status, 'MUCKED_SECRET');
      assert.equal(pos.opening, null);
    }

    // Export Alice's personalized proof: Alice sees her own hole cards, but Bob's mucked cards are STILL null!
    const aliceProof = session.exportHandProof('Alice');
    const aliceOwnPositions = aliceProof.dealtPositions.filter((p) => p.playerId === 'Alice');
    const bobFromAliceView = aliceProof.dealtPositions.filter((p) => p.playerId === 'Bob');
    assert.equal(aliceOwnPositions.every((p) => p.opening !== null && p.status === 'OPENED_PRIVATE'), true);
    assert.equal(bobFromAliceView.every((p) => p.opening === null && p.status === 'MUCKED_SECRET'), true);

    // Both publicProof and aliceProof pass full 7-stage cryptographic verification!
    assert.equal(verifyHandProof(publicProof).valid, true);
    assert.equal(verifyHandProof(aliceProof).valid, true);
  });

  it('6. Zero-Knowledge Deck Validity Proof detects duplicate cards (even sum-preserving duplicates!)', () => {
    const handId = 'test_zk_soundness_05';

    // Case A: Dishonest server creates a deck with two Aces of Spades (51) and no 2c (0)
    // Sum is 1326 + 51 = 1377 != 1326
    const badOrder1 = Array.from({ length: 52 }, (_, i) => (i === 0 ? 51 : i));
    const badDeck1 = createCommittedDeck(handId, badOrder1);
    const dummyPerm = Array.from({ length: 52 }, (_, i) => i);
    const badProof1 = generateZKDeckValidityProof(
      handId,
      badDeck1.deckRoot,
      badDeck1.secretRecords,
      dummyPerm
    );
    const verify1 = verifyZKDeckValidityProof(
      handId,
      badDeck1.deckRoot,
      badDeck1.publicEnvelopes,
      dummyPerm,
      badProof1
    );
    assert.equal(verify1.valid, false);
    assert.match(verify1.error ?? '', /Homomorphic sum invariant proof failed/);

    // Case B: Clever dishonest server replaces cards (1, 2) with (0, 3) so the sum is STILL 1326!
    // (two '2c's, two '5c's, zero '3c', zero '4c' -> sum of indices is still 1326!)
    // The Schwartz-Zippel Polynomial Grand-Product check MUST catch this!
    const sumPreservingBadOrder = Array.from({ length: 52 }, (_, i) => {
      if (i === 1) return 0; // duplicate 0
      if (i === 2) return 3; // duplicate 3
      return i;
    });
    const sumCheck = sumPreservingBadOrder.reduce((a, b) => a + b, 0);
    assert.equal(sumCheck, 1326); // Sum is indeed 1326!

    const badDeck2 = createCommittedDeck(handId, sumPreservingBadOrder);
    const badProof2 = generateZKDeckValidityProof(
      handId,
      badDeck2.deckRoot,
      badDeck2.secretRecords,
      dummyPerm
    );
    const verify2 = verifyZKDeckValidityProof(
      handId,
      badDeck2.deckRoot,
      badDeck2.publicEnvelopes,
      dummyPerm,
      badProof2
    );
    assert.equal(verify2.valid, false);
    assert.match(
      verify2.error ?? '',
      /Schwartz-Zippel Grand Product bijection proof failed/
    );
  });

  it('7. Circom 2.1 Groth16 witness builder satisfies all arithmetic circuit constraints', () => {
    const handId = 'test_circom_witness_06';
    const { secretRecords, deckRoot } = createCommittedDeck(handId);
    const perm = Array.from({ length: 52 }, (_, i) => (i * 7 + 3) % 52);
    const zkProof = generateZKDeckValidityProof(handId, deckRoot, secretRecords, perm);

    const witness = buildCircomDeckShuffleWitnessInput(
      secretRecords,
      perm,
      zkProof.fiatShamirChallengeHex
    );

    const gamma = BigInt(witness.fiatShamirChallenge);
    let committedProd = 1n;
    let canonicalProd = 1n;

    for (let i = 0; i < 52; i++) {
      const card = BigInt(witness.cards[i]);
      const salt = BigInt(witness.salts[i]);
      const expectedCom = computeCircuitFieldCommitment(Number(card), salt, i);
      assert.equal(BigInt(witness.initialCommitments[i]), expectedCom);

      committedProd =
        (committedProd * ((gamma - card + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD)) %
        BN254_SCALAR_FIELD;
      canonicalProd =
        (canonicalProd * ((gamma - BigInt(i) + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD)) %
        BN254_SCALAR_FIELD;
    }

    // Grand Product bijection constraint in F_r
    assert.equal(committedProd, canonicalProd);

    // Shuffle routing constraint
    for (let j = 0; j < 52; j++) {
      const pIdx = Number(witness.permutation[j]);
      assert.equal(witness.shuffledCommitments[j], witness.initialCommitments[pIdx]);
    }
  });
});
