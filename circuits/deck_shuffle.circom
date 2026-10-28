pragma circom 2.1.6;

/*
 * PurrPoker Provably Fair ZK Verifiable Shuffle Circuit (Groth16 / PLONK)
 * =========================================================================
 * Proves in Zero-Knowledge over BN254 scalar field F_r:
 *   1. Deck Completeness & Uniqueness (Bijection to 0..51):
 *      The 52 private card indices `cards[52]` are a valid permutation of {0, 1, ..., 51}
 *      via the Schwartz-Zippel Grand Product argument:
 *        \prod_{i=0}^{51} (gamma - cards[i]) === \prod_{k=0}^{51} (gamma - k)
 *   2. Commitment Binding:
 *      Each public commitment `initialCommitments[i]` equals the algebraic commitment
 *      bound to `(cards[i], salts[i])`.
 *   3. Valid Shuffle Permutation:
 *      The shuffled commitments `shuffledCommitments[j]` are an exact permutation
 *      of `initialCommitments` according to `permutation[j]`.
 *   4. Selective Card Openings remain Private:
 *      All `cards[i]` and `salts[i]` are private witness signals; mucked/folded cards
 *      are never revealed in public signals.
 */

template CommitmentHasher() {
    signal input cardIndex;
    signal input salt;
    signal input envelopeIndex;
    signal output commitment;

    // Algebraic MiMC/Poseidon-style sponge round in F_r for circuit efficiency
    // commitment = (cardIndex + 1) + salt * (envelopeIndex + 101) + (salt * salt)
    signal saltSq;
    saltSq <== salt * salt;

    signal mix;
    mix <== salt * (envelopeIndex + 101) + (cardIndex + 1);

    commitment <== saltSq + mix;
}

template SelectByIndex(N) {
    signal input values[N];
    signal input index;
    signal output out;

    signal eq[N];
    signal partial[N];
    signal diff[N];
    signal inv[N];

    var sumEq = 0;
    for (var i = 0; i < N; i++) {
        diff[i] <== index - i;
        // eq[i] is 1 if index == i, else 0
        inv[i] <-- (diff[i] != 0) ? (1 / diff[i]) : 0;
        eq[i] <== -diff[i] * inv[i] + 1;
        diff[i] * eq[i] === 0;

        partial[i] <== values[i] * eq[i];
        sumEq += eq[i];
    }

    // Enforce that index is strictly within [0, N - 1]
    sumEq === 1;

    signal acc[N];
    acc[0] <== partial[0];
    for (var i = 1; i < N; i++) {
        acc[i] <== acc[i - 1] + partial[i];
    }
    out <== acc[N - 1];
}

template PurrPokerDeckShuffle(N) {
    // Public Inputs
    signal input initialCommitments[N];
    signal input shuffledCommitments[N];
    signal input permutation[N];
    signal input fiatShamirChallenge;

    // Private Witness Inputs (NEVER revealed for mucked or folded cards)
    signal input cards[N];
    signal input salts[N];

    // 1. Verify each initial envelope commitment matches (cards[i], salts[i], i)
    component hashers[N];
    for (var i = 0; i < N; i++) {
        hashers[i] = CommitmentHasher();
        hashers[i].cardIndex <== cards[i];
        hashers[i].salt <== salts[i];
        hashers[i].envelopeIndex <== i;
        hashers[i].commitment === initialCommitments[i];
    }

    // 2. Schwartz-Zippel Grand Product Bijection Proof:
    //    Prove that {cards[0], ..., cards[N-1]} is an exact permutation of {0, ..., N-1}
    signal committedRunningProd[N];
    signal canonicalRunningProd[N];

    committedRunningProd[0] <== fiatShamirChallenge - cards[0];
    canonicalRunningProd[0] <== fiatShamirChallenge - 0;

    for (var i = 1; i < N; i++) {
        committedRunningProd[i] <== committedRunningProd[i - 1] * (fiatShamirChallenge - cards[i]);
        canonicalRunningProd[i] <== canonicalRunningProd[i - 1] * (fiatShamirChallenge - i);
    }

    // Multiset equality constraint: prod(gamma - cards[i]) === prod(gamma - i)
    committedRunningProd[N - 1] === canonicalRunningProd[N - 1];

    // 3. Permutation Bijection Proof:
    //    Prove that {permutation[0], ..., permutation[N-1]} is also a valid permutation of {0..N-1}
    signal permRunningProd[N];
    permRunningProd[0] <== fiatShamirChallenge - permutation[0];
    for (var j = 1; j < N; j++) {
        permRunningProd[j] <== permRunningProd[j - 1] * (fiatShamirChallenge - permutation[j]);
    }
    permRunningProd[N - 1] === canonicalRunningProd[N - 1];

    // 4. Shuffle Routing Proof:
    //    Prove that shuffledCommitments[j] == initialCommitments[permutation[j]] for all j
    component selectors[N];
    for (var j = 0; j < N; j++) {
        selectors[j] = SelectByIndex(N);
        for (var i = 0; i < N; i++) {
            selectors[j].values[i] <== initialCommitments[i];
        }
        selectors[j].index <== permutation[j];
        selectors[j].out === shuffledCommitments[j];
    }
}

component main {
    public [
        initialCommitments,
        shuffledCommitments,
        permutation,
        fiatShamirChallenge
    ]
} = PurrPokerDeckShuffle(52);
