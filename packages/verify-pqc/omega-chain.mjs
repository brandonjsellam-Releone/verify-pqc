/*!
 * omega-chain — TRELYAN OMEGA Layer 2 (Chain) event-anchoring artifact (reference, DRAFT). Batches OMEGA events
 * (governance decisions, QIV inscriptions, capability attestations, key-derivation attestations) into a hash-chained
 * PQ-signed log (pqauditlog: Ed25519 ∧ ML-DSA-87 [∧ SLH-DSA]) and binds the batch to an Algorand anchor (pqanchor),
 * producing the EXACT note/calldata bytes you would post on-chain — and the offline proof that those bytes bind THIS
 * batch. Composition only; adds no crypto.
 *
 * HONEST: this DOES NOT broadcast. It emits `anchorCalldata` / `commitment` — the precise bytes a funded account would
 * post to the Algorand app (TRELYAN's live PQ chain) — exactly as pqanchor does; actual posting needs a funded signer +
 * a deployed app and is OWNER-GATED. Anchoring proves the off-chain↔on-chain BINDING, not chain honesty/availability or
 * "immutability". Falcon-1024 (FIPS 206 DRAFT) is the separate on-chain inscription/verify leg; the anchor authority
 * here signs Ed25519 ∧ ML-DSA-87 (FIPS 204). Self-test: node omega-chain.mjs
 */
import { createLog, append, exportLog, verifyLog } from './pqauditlog.mjs';
import { createAnchorChain, appendAnchor, anchorCalldata, onchainCommitment, verifyAnchored } from './pqanchor.mjs';
import { bytesToHex } from '@noble/hashes/utils.js';

// OMEGA event kind → pqauditlog custody stage (STAGES = input,signal,decision,execution,ledger)
const KIND_STAGE = { governance: 'decision', vault: 'execution', capability: 'execution', keyattest: 'execution', anchor: 'ledger' };
export const OMEGA_EVENT_KINDS = Object.keys(KIND_STAGE);

/** openChain(logSigner, anchorSigner) — signers are { ed:{secretKey,publicKey}, mldsa:{...}, slh?:{...} }.
 *  logSigner authenticates events; anchorSigner is the ledger authority that signs anchors. */
export function openChain(logSigner, anchorSigner, opts = {}) {
  if (!logSigner || !logSigner.ed || !logSigner.mldsa) throw new Error('omega-chain: logSigner must be { ed, mldsa }');
  if (!anchorSigner || !anchorSigner.ed || !anchorSigner.mldsa) throw new Error('omega-chain: anchorSigner must be { ed, mldsa }');
  return {
    log: createLog(logSigner),
    achain: createAnchorChain(anchorSigner, { chain: opts.chain || 'algorand' }),
    logSigner, anchorSigner,
    logPub: { ed: logSigner.ed.publicKey, mldsa: logSigner.mldsa.publicKey },
    anchorPub: { ed: anchorSigner.ed.publicKey, mldsa: anchorSigner.mldsa.publicKey },
  };
}

/** recordEvent(chain, { kind, actor, payload, ts, parentSeq }) — append one OMEGA event to the log. */
export function recordEvent(chain, { kind, actor, payload, ts, parentSeq }) {
  const stage = KIND_STAGE[kind];
  if (!stage) throw new Error('omega-chain: unknown event kind: ' + kind + ' (allowed: ' + OMEGA_EVENT_KINDS.join(',') + ')');
  return append(chain.log, { actor: actor || kind, action: kind, stage, payload: payload ?? '', ts, parentSeq });
}

/**
 * sealBatch(chain, { ts }) — verify the current log, anchor its tip, and return the on-chain bytes + offline proof.
 * Returns { entries, anchor, commitment, calldata, n, log_root }. NOT broadcast.
 */
export function sealBatch(chain, { ts } = {}) {
  const entries = exportLog(chain.log);
  const lv = verifyLog(entries, { ed: chain.logPub.ed, mldsa: chain.logPub.mldsa });
  if (!lv.verified) throw new Error('omega-chain: log does not verify (' + lv.reason + ')');
  const anchor = appendAnchor(chain.achain, { root: lv.tip, n: lv.n, logSignerPubs: { ed: bytesToHex(chain.logPub.ed), mldsa: bytesToHex(chain.logPub.mldsa) } }, { ts: ts ?? (entries.length ? entries[entries.length - 1].ts : 0) });
  return {
    entries, anchor, n: lv.n, log_root: lv.tip,
    commitment: onchainCommitment(anchor),   // the 32-byte on-chain commitment to post (Algorand note)
    calldata: anchorCalldata(anchor),         // deterministic versioned wire bytes
    chain: chain.achain.chain, broadcast: false,
  };
}

/**
 * verifyBatch(batch, trusted) — TOTAL / fail-closed. trusted = { log:{ed,mldsa}, anchor:{ed,mldsa} } (Uint8Array pubs).
 * Verifies the log integrity + that the anchor binds this exact batch to the given commitment.
 */
export function verifyBatch(batch, trusted) {
  try {
    if (!batch || !batch.entries || !batch.anchor) return { verified: false, reason: 'shape' };
    // defensive (on top of verifyAnchored's own commitmentOk): the supplied commitment must equal the canonical
    // commitment derived from THIS anchor, so a mismatched commitment field is rejected before the full check.
    if (batch.commitment !== onchainCommitment(batch.anchor)) return { verified: false, reason: 'commitment != canonical anchor hash' };
    const va = verifyAnchored(batch.entries, batch.anchor, batch.commitment, trusted);
    return { verified: va.verified, logOk: va.logOk, anchorSigOk: va.anchorSigOk, commitmentOk: va.commitmentOk, n: va.n, reason: va.reason };
  } catch { return { verified: false, reason: 'exception' }; }
}

/* ---------------------------------------- self-test: node omega-chain.mjs ---------------------------------------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const s = (n) => new Uint8Array(32).fill(n);
  const ed = (n) => { const sk = s(n); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  const logSigner = { ed: ed(1), mldsa: ml_dsa87.keygen(s(2)) };
  const anchorSigner = { ed: ed(3), mldsa: ml_dsa87.keygen(s(4)) };
  const trusted = { log: { ed: logSigner.ed.publicKey, mldsa: logSigner.mldsa.publicKey }, anchor: { ed: anchorSigner.ed.publicKey, mldsa: anchorSigner.mldsa.publicKey } };

  const chain = openChain(logSigner, anchorSigner);
  recordEvent(chain, { kind: 'governance', actor: 'board', payload: { proposal: 'adopt_omega', executable: true }, ts: 1 });
  recordEvent(chain, { kind: 'vault', actor: 'vault', payload: { cell_id: 42, ip: 'patent' }, ts: 2 });
  recordEvent(chain, { kind: 'capability', actor: 'issuer', payload: { omega_version: '0.1.0-draft' }, ts: 3 });
  const batch = sealBatch(chain, { ts: 3 });
  ok(batch.n === 3 && batch.broadcast === false, 'sealBatch: 3 events anchored, not broadcast');
  ok(batch.commitment.length === 64 && batch.calldata.length > 0, 'sealBatch: commitment + calldata produced');

  const v = verifyBatch(batch, trusted);
  ok(v.verified && v.logOk && v.anchorSigOk && v.commitmentOk, 'verifyBatch: full binding verifies');

  // wrong anchor authority → fails
  const badTrust = { log: trusted.log, anchor: { ed: ed(9).publicKey, mldsa: ml_dsa87.keygen(s(10)).publicKey } };
  ok(!verifyBatch(batch, badTrust).verified, 'verifyBatch: wrong anchor authority rejected');

  // tamper an event payload → log/commitment fails
  const tampered = JSON.parse(JSON.stringify(batch)); tampered.entries[1].actor = 'attacker';
  ok(!verifyBatch(tampered, trusted).verified, 'verifyBatch: tampered event rejected');

  // wrong commitment → fails
  const badCommit = { ...batch, commitment: batch.commitment.slice(0, -2) + (batch.commitment.endsWith('00') ? '01' : '00') };
  ok(!verifyBatch(badCommit, trusted).verified, 'verifyBatch: wrong on-chain commitment rejected');

  // unknown event kind → rejected
  let threw = false; try { recordEvent(chain, { kind: 'token_sale', actor: 'x', ts: 4 }); } catch { threw = true; }
  ok(threw, 'recordEvent: unknown event kind rejected');

  console.log(`\nomega-chain self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
