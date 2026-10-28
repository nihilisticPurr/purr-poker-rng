#!/usr/bin/env node
/**
 * @purr-poker/rng - Command Line Verifier & Interactive Hand Proof Demo
 *
 * Usage:
 *   npx purr-poker-rng <hand-proof.json>
 *   npm run verify:demo
 */

import fs from 'node:fs';
import path from 'node:path';
import { ProvablyFairHandSession } from '../server-adapter.ts';
import { verifyHandProof } from '../verifier.ts';
import type { PublicHandProof } from '../types.ts';

export function generateSampleHandProof(): PublicHandProof {
  const session = new ProvablyFairHandSession({
    handId: 'hand_purr_20261028_0001',
    tableId: '0x7a9E4C1B28F00429D8fE1234567890abCDef0001',
    kdfMode: 'SHAKE256',
  });

  // 3 players commit 256-bit entropy before locking
  session.commitAndQueuePlayerEntropy('0xAlice_Seat0', 0);
  session.commitAndQueuePlayerEntropy('0xBob_Seat1', 1);
  session.commitAndQueuePlayerEntropy('0xCarol_Seat2', 2);

  // Lock commitments, reveal all 256-bit entropy seeds, run unbiased Fisher-Yates & generate ZK Deck Proof
  session.lockCommitmentsAndShuffle();

  // Deal 2 hole cards to each player
  session.dealHoleCards([
    { seatIndex: 0, playerId: '0xAlice_Seat0' },
    { seatIndex: 1, playerId: '0xBob_Seat1' },
    { seatIndex: 2, playerId: '0xCarol_Seat2' },
  ]);

  // Deal Flop, Turn, River (with burn cards kept secret)
  session.dealCommunityStage('FLOP', true);
  session.dealCommunityStage('TURN', true);
  session.dealCommunityStage('RIVER', true);

  // Alice and Bob reach Showdown and reveal hands; Carol folded on the Turn (her hole cards stay permanently secret!)
  session.revealShowdownHand('0xAlice_Seat0');
  session.revealShowdownHand('0xBob_Seat1');

  return session.exportHandProof();
}

function printReport(proof: PublicHandProof): boolean {
  const report = verifyHandProof(proof);

  console.log('========================================================================');
  console.log('  PURRPOKER PROVABLY FAIR & ZERO-KNOWLEDGE HAND VERIFIER (v1.0.0)');
  console.log('========================================================================');
  console.log(`Hand ID           : ${proof.handId}`);
  console.log(`Table ID          : ${proof.tableId}`);
  console.log(`KDF Algorithm     : ${proof.kdfMode}`);
  console.log(`Deck Merkle Root  : ${proof.deckRoot}`);
  console.log(`Master Seed (256b): ${proof.masterSeedHex}`);
  console.log(`ZK Protocol       : ${proof.zkDeckProof.protocol}`);
  console.log(`ZK FS Challenge   : ${proof.zkDeckProof.fiatShamirChallengeHex}`);
  console.log('------------------------------------------------------------------------');
  console.log('CRYPTOGRAPHIC AUDIT CHECKS:');
  for (const check of report.checks) {
    const badge = check.passed ? '[PASS]' : '[FAIL]';
    console.log(`  ${badge} ${check.name}`);
    console.log(`         ${check.details}`);
  }
  console.log('------------------------------------------------------------------------');
  console.log('DEALT CARDS & SELECTIVE OPENINGS SUMMARY:');
  for (const pos of proof.dealtPositions) {
    if (pos.opening) {
      const owner =
        pos.seatIndex !== undefined ? `Seat ${pos.seatIndex} (${pos.playerId})` : 'Community Board';
      console.log(
        `  Pos #${String(pos.shuffledPosition).padStart(2, '0')} -> Envelope #${String(
          pos.initialEnvelopeIndex
        ).padStart(2, '0')} | [${pos.stage.padEnd(9, ' ')}] ${pos.opening.cardCode} (${
          pos.opening.card.rankDisplay
        }${pos.opening.card.suitDisplay}) | ${owner} | Salt: ${pos.opening.saltHex.slice(0, 12)}...`
      );
    } else {
      const owner =
        pos.seatIndex !== undefined
          ? `Seat ${pos.seatIndex} (${pos.playerId} - MUCKED/FOLDED)`
          : `${pos.stage} (SEALED)`;
      console.log(
        `  Pos #${String(pos.shuffledPosition).padStart(2, '0')} -> Envelope #${String(
          pos.initialEnvelopeIndex
        ).padStart(2, '0')} | [${pos.status.padEnd(14, ' ')}] ** [256-Bit Salt Permanently Withheld] | ${owner}`
      );
    }
  }
  console.log('========================================================================');
  console.log(`RESULT: ${report.summary}`);
  console.log('========================================================================');

  return report.valid;
}

const args = process.argv.slice(2);
if (args.length > 0) {
  if (args[0] === '--demo') {
    const sampleProof = generateSampleHandProof();
    const ok = printReport(sampleProof);
    process.exit(ok ? 0 : 1);
  } else if (args[0] === '--export-sample' && args[1]) {
    const sampleProof = generateSampleHandProof();
    const outPath = path.resolve(process.cwd(), args[1]);
    fs.writeFileSync(outPath, JSON.stringify(sampleProof, null, 2), 'utf8');
    console.log(`Exported sample PublicHandProof JSON to ${outPath}`);
    process.exit(0);
  } else {
    const targetFile = path.resolve(process.cwd(), args[0]);
    const raw = fs.readFileSync(targetFile, 'utf8');
    const proof = JSON.parse(raw) as PublicHandProof;
    const ok = printReport(proof);
    process.exit(ok ? 0 : 1);
  }
}
