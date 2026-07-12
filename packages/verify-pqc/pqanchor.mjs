/*!
 * pqanchor — bind a pqauditlog trail to a LEDGER-OF-RECORD anchor (the QLR ledger role in Apex's dual-chain design), and
 * verify the binding (reference, DRAFT). The CANONICAL ledger is Algorand — TRELYAN's live PQ chain (Falcon-1024 via the
 * on-chain falcon_verify opcode; 1,024 Vault Cells; the dual-chain PDF + the live site both define QLR = Algorand). QRL 2.0
 * / Project Zond (github.com/theQRL; EVM-compatible PQ L1, ML-DSA-87 native via the Hyperion compiler; Testnet V2 Mar 2026)
 * is supported as an OPTIONAL second PQ chain — the same ML-DSA-87 our anchor uses is verifiable there. This is the "write
 * to the ledger, tamper-proof + timestamped" step done honestly: the FULL audit log
 * stays off-chain; only a small, hybrid-signed ANCHOR (the log's root hash + metadata) is committed on-chain, and the
 * off-chain log is hash-bound to that on-chain commitment — the same off-chain-artifact -> on-chain-Cell hash-binding the
 * TRELYAN inscription protocol uses (IPFS/Arweave bound to an Algorand Cell).
 *
 * It deliberately does NOT broadcast to any chain: actual posting to Algorand (the canonical QLR — a funded account + a
 * deployed app) — or optionally QRL Zond — needs a funded signer + a deployed contract and is owner-gated. pqanchor produces
 * the exact bytes you would post (`anchorCalldata` / `onchainCommitment`) and verifies, after the fact, that a given
 * on-chain commitment provably binds a specific off-chain log state.
 *
 * NOVEL FALSIFIABLE PROPERTY: given the off-chain log + an on-chain commitment + the pinned log-signer AND anchor-signer
 * keys, a third party can confirm (1) the log itself verifies (pqauditlog: hash-chained + Ed25519∧ML-DSA-87 dual-signed +
 * replay-proof), (2) the anchor's `log_root` equals the log's tip and names the correct log signer, (3) the anchor is
 * itself dual-signed by the pinned ledger authority, and (4) the on-chain commitment equals this exact anchor's hash —
 * i.e. THIS log state, and no other, is the one committed on the QRL chain. Anchors also form their own hash-chain
 * (prev_anchor), so a sequence of periodic anchors is tamper-evident against drop/reorder. HONEST: this proves the
 * binding off-chain↔on-chain; it does not prove the chain itself is honest/available (that is the ledger's job), and it
 * proves nothing was posted until a real transaction carrying `onchainCommitment` exists on-chain.
 *
 * Dependency-light: @noble/curves (ed25519) + @noble/post-quantum (ml-dsa-87) + @noble/hashes (sha256) + ./pqauditlog.
 * Self-test: node pqanchor.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { verifyLog } from './pqauditlog.mjs';

const ANCHOR_CTX = utf8ToBytes('trelyan-qrl-anchor-v1');        // signing domain (Ed25519 + ML-DSA legs)
const ANCHOR_SLH_CTX = utf8ToBytes('trelyan-qrl-anchor-slh-v1'); // distinct domain for the optional SLH-DSA hash-based leg
const ANCHOR_HASH_TAG = utf8ToBytes('trelyan-qrl-anchor-hash-v1');
const GENESIS = '0'.repeat(64);
// target ledger encodings. algorand = CANONICAL QLR (TRELYAN's live Falcon-1024 chain). qrl-zond = optional QRL 2.0 /
// Project Zond (EVM-compatible PQ L1; ML-DSA-87 native via Hyperion; Testnet V2 Mar 2026). qrl = legacy QRL PoW (XMSS, stateful).
const CHAINS = ['algorand', 'qrl-zond', 'qrl', 'generic'];

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
// signable core of an anchor (everything except the signatures + derived anchor_hash)
function anchorCore(a) {
  return { v: '1', chain: a.chain, seq: a.seq, ts: a.ts, n: a.n, log_root: a.log_root,
    log_signer: { ed: a.log_signer.ed, mldsa: a.log_signer.mldsa }, prev_anchor: a.prev_anchor };
}
const anchorHashOf = (coreBytes) => bytesToHex(sha256(concatBytes(ANCHOR_HASH_TAG, coreBytes)));
const u64hex = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return bytesToHex(b); };

// anchorSigner = { ed:{secretKey,publicKey}, mldsa:{secretKey,publicKey} } — the LEDGER AUTHORITY that signs anchors.
export function createAnchorChain(anchorSigner, opts = {}) {
  if (!anchorSigner || !anchorSigner.ed || !anchorSigner.mldsa) throw new Error('anchorSigner must be { ed, mldsa } keypairs');
  const anchor_signer_pub = { ed: bytesToHex(anchorSigner.ed.publicKey), mldsa: bytesToHex(anchorSigner.mldsa.publicKey) };
  if (anchorSigner.slh) anchor_signer_pub.slh = bytesToHex(anchorSigner.slh.publicKey);  // optional hash-based 3rd leg
  return { anchors: [], signer: anchorSigner, chain: CHAINS.includes(opts.chain) ? opts.chain : 'algorand', anchor_signer_pub };
}

// tip = { root, n, logSignerPubs:{ ed:hex, mldsa:hex } } — typically taken from verifyLog(entries, pinnedLogKeys).
export function appendAnchor(achain, tip, opts = {}) {
  if (!tip || typeof tip.root !== 'string' || typeof tip.n !== 'number' || !tip.logSignerPubs) throw new Error('tip must be { root, n, logSignerPubs }');
  const last = achain.anchors[achain.anchors.length - 1];
  const seq = achain.anchors.length;
  const ts = opts.ts ?? (last ? last.ts : 0);
  if (last && ts < last.ts) throw new Error('ts must be non-decreasing');
  const core = anchorCore({ chain: achain.chain, seq, ts, n: tip.n, log_root: tip.root,
    log_signer: { ed: tip.logSignerPubs.ed, mldsa: tip.logSignerPubs.mldsa }, prev_anchor: last ? last.anchor_hash : GENESIS });
  const coreBytes = utf8ToBytes(canon(core));
  const anchor = { ...core,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(ANCHOR_CTX, coreBytes), achain.signer.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, achain.signer.mldsa.secretKey, { context: ANCHOR_CTX })),
    anchor_hash: anchorHashOf(coreBytes) };
  if (achain.signer.slh) anchor.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, achain.signer.slh.secretKey, { context: ANCHOR_SLH_CTX }));
  achain.anchors.push(anchor);
  return anchor;
}

// the 32-byte on-chain commitment to post to the ledger (Algorand canonical; the full anchor lives off-chain, hash-bound to this).
export const onchainCommitment = (anchor) => anchor.anchor_hash;

// a deterministic, versioned wire encoding to post on the target chain (EVM calldata hex / Algorand note):
//   "TRLNA1" | chain-tag(2 hex) | seq(8B) | log_root(32B) | anchor_hash(32B)
export function anchorCalldata(anchor) {
  const tag = { 'qrl-zond': '01', 'qrl': '03', 'algorand': '02', 'generic': '00' }[anchor.chain] ?? '00';
  const body = tag + u64hex(anchor.seq) + anchor.log_root + anchor.anchor_hash;
  const hex = bytesToHex(utf8ToBytes('TRLNA1')) + body;
  return anchor.chain === 'qrl-zond' ? '0x' + hex : hex;   // Zond is EVM-compatible -> 0x calldata
}

// verify ONE anchor binds a given off-chain log to a given on-chain commitment. TOTAL / fail-closed.
// trusted = { log:{ ed, mldsa }, anchor:{ ed, mldsa } } (Uint8Array pubkeys). opts.logOpts forwarded to verifyLog.
export function verifyAnchored(logEntries, anchor, onchainCommitmentHex, trusted, opts = {}) {
  const fail = (reason) => ({ verified: false, logOk: false, rootOk: false, anchorSigOk: false, commitmentOk: false, reason });
  try {
    if (!anchor || typeof anchor !== 'object' || !trusted || !trusted.log || !trusted.anchor) return fail('args');
    const lv = verifyLog(logEntries, trusted.log, opts.logOpts || {});
    if (!lv.verified) return fail('log does not verify: ' + lv.reason);
    const coreBytes = utf8ToBytes(canon(anchorCore(anchor)));
    // (2) the anchor commits to THIS log's tip + count, and names the correct log signer
    const rootOk = anchor.log_root === lv.tip && anchor.n === lv.n
      && anchor.log_signer && anchor.log_signer.ed === bytesToHex(trusted.log.ed) && anchor.log_signer.mldsa === bytesToHex(trusted.log.mldsa);
    if (!rootOk) return { ...fail('anchor does not bind this log tip/signer'), logOk: true };
    // (3) the anchor is dual-signed by the pinned ledger authority (AND-composition: no downgrade)
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(anchor.ed_sig), concatBytes(ANCHOR_CTX, coreBytes), trusted.anchor.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(anchor.mldsa_sig), coreBytes, trusted.anchor.mldsa, { context: ANCHOR_CTX }); } catch { pqOk = false; }
    if (trusted.anchor.slh) { try { slhOk = !!(anchor.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(anchor.slh_sig), coreBytes, trusted.anchor.slh, { context: ANCHOR_SLH_CTX })); } catch { slhOk = false; } }
    const anchorSigOk = edOk && pqOk && slhOk;  // AND-composition incl. the optional hash-based leg when pinned
    // (4) the on-chain commitment equals this exact anchor's hash
    const computed = anchorHashOf(coreBytes);
    const commitmentOk = computed === anchor.anchor_hash && computed === String(onchainCommitmentHex).toLowerCase();
    return { verified: lv.verified && rootOk && anchorSigOk && commitmentOk, logOk: true, rootOk, anchorSigOk, edOk, pqOk, commitmentOk, log_root: lv.tip, n: lv.n, reason: anchorSigOk && commitmentOk ? 'ok' : (!anchorSigOk ? 'anchor signature invalid' : 'commitment mismatch') };
  } catch { return fail('exception'); }
}

// verify a CHAIN of periodic anchors (links + signs + monotonic ts). TOTAL / fail-closed. opts.expectedTip pins the
// known latest anchor_hash and opts.minLength a known minimum, so TAIL-TRUNCATION/rollback (invisible from a chain
// alone) becomes detectable; opts.requireMonotonicN rejects an anchored log-state rollback (n decreasing across anchors).
export function verifyAnchorChain(anchors, trustedAnchor, opts = {}) {
  const base = { verified: false, n: 0, broken_at: 0, reason: '' };
  try {
    if (!Array.isArray(anchors) || !trustedAnchor || !trustedAnchor.ed || !trustedAnchor.mldsa) return { ...base, reason: 'args' };
    let prev = GENESIS, lastTs = -Infinity, lastN = -1, firstLogSigner = null;
    // optional out-of-band pin of the expected log signer (hex). Without it, we still enforce the log signer is CONSTANT
    // across the chain (sweep R1): a silent mid-chain log_signer swap — e.g. a compromised anchor authority re-anchoring a
    // different log — must not pass; key rotation has to be an explicit, separately-verified event, not an unnoticed change.
    const pinLog = opts.trustedLog ? { ed: bytesToHex(opts.trustedLog.ed), mldsa: bytesToHex(opts.trustedLog.mldsa) } : null;
    for (let i = 0; i < anchors.length; i++) {
      const a = anchors[i]; const at = (reason) => ({ ...base, n: anchors.length, broken_at: i, reason });
      if (!a || a.seq !== i) return at('seq/shape');
      const coreBytes = utf8ToBytes(canon(anchorCore(a)));
      if (a.prev_anchor !== prev) return at('anchor chain linkage');
      if (!a.log_signer || typeof a.log_signer.ed !== 'string' || typeof a.log_signer.mldsa !== 'string') return at('anchor missing log_signer');
      if (i === 0) firstLogSigner = a.log_signer;
      else if (a.log_signer.ed !== firstLogSigner.ed || a.log_signer.mldsa !== firstLogSigner.mldsa) return at('log_signer changed mid-chain (silent log-key swap rejected)');
      if (pinLog && (a.log_signer.ed !== pinLog.ed || a.log_signer.mldsa !== pinLog.mldsa)) return at('anchor log_signer != pinned trustedLog');
      if (anchorHashOf(coreBytes) !== a.anchor_hash) return at('anchor_hash mismatch (tamper)');
      if (!CHAINS.includes(a.chain)) return at('unknown chain tag');
      if (typeof a.ts !== 'number' || a.ts < lastTs) return at('ts not non-decreasing');
      if (opts.requireMonotonicN && typeof a.n === 'number' && a.n < lastN) return at('log-state rollback (anchored n decreased across the chain)');
      let edOk = false, pqOk = false;
      try { edOk = ed25519.verify(hexToBytes(a.ed_sig), concatBytes(ANCHOR_CTX, coreBytes), trustedAnchor.ed); } catch { edOk = false; }
      try { pqOk = ml_dsa87.verify(hexToBytes(a.mldsa_sig), coreBytes, trustedAnchor.mldsa, { context: ANCHOR_CTX }); } catch { pqOk = false; }
      if (!edOk) return at('Ed25519 anchor signature invalid');
      if (!pqOk) return at('ML-DSA-87 anchor signature invalid (or PQ leg stripped)');
      if (trustedAnchor.slh) { let slhOk = false; try { slhOk = !!(a.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(a.slh_sig), coreBytes, trustedAnchor.slh, { context: ANCHOR_SLH_CTX })); } catch { slhOk = false; } if (!slhOk) return at('SLH-DSA hash-based anchor leg invalid/missing (required when trustedAnchor.slh pinned)'); }
      prev = a.anchor_hash; lastTs = a.ts; lastN = a.n;
    }
    // tail-truncation / rollback is undetectable from the chain alone — a caller who knows the latest anchor pins it.
    const tip = anchors.length ? anchors[anchors.length - 1].anchor_hash : GENESIS;
    if (opts.minLength != null && anchors.length < opts.minLength) return { ...base, n: anchors.length, broken_at: Math.max(0, anchors.length - 1), reason: 'chain shorter than expected minLength (tail truncation?)' };
    if (opts.expectedTip != null && String(opts.expectedTip).toLowerCase() !== tip.toLowerCase()) return { ...base, n: anchors.length, broken_at: Math.max(0, anchors.length - 1), reason: 'tip != expectedTip (tail truncation / fork)' };
    return { verified: true, n: anchors.length, broken_at: -1, reason: 'ok', tip };
  } catch { return base; }
}

// ---- DUAL-CHAIN: anchor the SAME log/Cell root to TWO ledgers at once (default Algorand + QRL-Zond) ----
// WHY both: Algorand is the live inscription substrate (Falcon-1024 / falcon_verify), but a standard Algorand account
// signs with Ed25519 — quantum-vulnerable at the WALLET layer (a Falcon logic-sig can harden it, but that is the
// default-Ed25519 caveat). QRL is PQ-native at the wallet layer (XMSS / ML-DSA-87 on Zond). Committing to BOTH means the
// record survives even if one chain's account layer is broken by a CRQC. These are two independent anchor chains.
export function createDualAnchor(anchorSigner, opts = {}) {
  return { primary: createAnchorChain(anchorSigner, { chain: opts.primary || 'algorand' }),
    secondary: createAnchorChain(anchorSigner, { chain: opts.secondary || 'qrl-zond' }) };
}
// append the same tip to both chains; returns both anchors + the per-chain on-chain commitments you would post.
export function appendDual(dual, tip, opts = {}) {
  const primary = appendAnchor(dual.primary, tip, opts);
  const secondary = appendAnchor(dual.secondary, tip, opts);
  return { primary, secondary, commitments: { [dual.primary.chain]: onchainCommitment(primary), [dual.secondary.chain]: onchainCommitment(secondary) } };
}
// verify BOTH anchors bind the SAME off-chain log (TOTAL / fail-closed). dual = { primary, secondary } anchors.
export function verifyDual(logEntries, dual, trusted, opts = {}) {
  try {
    if (!dual || !dual.primary || !dual.secondary) return { verified: false };
    const p = verifyAnchored(logEntries, dual.primary, onchainCommitment(dual.primary), trusted, opts);
    const s = verifyAnchored(logEntries, dual.secondary, onchainCommitment(dual.secondary), trusted, opts);
    const sameRoot = dual.primary.log_root === dual.secondary.log_root;
    return { verified: !!(p.verified && s.verified && sameRoot), dual_bound: !!(p.verified && s.verified && sameRoot), primary: p, secondary: s, chains: [dual.primary.chain, dual.secondary.chain] };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqanchor.mjs ---------- */
async function selfTest() {
  const { createLog, append } = await import('./pqauditlog.mjs');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const logSigner = { ed: ed(3), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(4)) };
  const anchorSigner = { ed: ed(5), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(6)) };
  const trustedLog = { ed: logSigner.ed.publicKey, mldsa: logSigner.mldsa.publicKey };
  const trustedAnchor = { ed: anchorSigner.ed.publicKey, mldsa: anchorSigner.mldsa.publicKey };
  const trusted = { log: trustedLog, anchor: trustedAnchor };

  // build a real audit log, take its verified tip, anchor it
  const log = createLog(logSigner);
  append(log, { actor: 'feed', action: 'tick', stage: 'input', ts: 1 });
  append(log, { actor: 'council', action: 'vote UP', stage: 'signal', ts: 2, parentSeq: 0 });
  append(log, { actor: 'risk', action: 'GO', stage: 'decision', ts: 3, parentSeq: 1 });
  const entries = log.entries.map((e) => ({ ...e }));
  const lv = verifyLog(entries, trustedLog);
  const achain = createAnchorChain(anchorSigner, { chain: 'qrl-zond' });
  const a0 = appendAnchor(achain, { root: lv.tip, n: lv.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 4 });

  // happy path
  const v = verifyAnchored(entries, a0, onchainCommitment(a0), trusted);
  ok(v.verified === true, 'happy: anchor binds the verified log tip + matches the on-chain commitment, dual-signed by the ledger authority');
  ok(/^0x54524c4e413101/.test(anchorCalldata(a0)), 'EVM calldata is the versioned TRLNA1 encoding (0x-prefixed)');

  // failure: wrong on-chain commitment
  ok(verifyAnchored(entries, a0, '00'.repeat(32), trusted).verified === false, 'wrong on-chain commitment -> FAILS');
  // failure: anchor binds a DIFFERENT log state (append more, tip moves) -> old anchor no longer matches new log
  append(log, { actor: 'oms', action: 'SIM order', stage: 'execution', ts: 5, parentSeq: 2 });
  const entries2 = log.entries.map((e) => ({ ...e }));
  const r2 = verifyAnchored(entries2, a0, onchainCommitment(a0), trusted);
  ok(r2.verified === false && r2.rootOk === false, 'anchor checked against a MUTATED log (extra entry) -> FAILS (binds a specific state)');
  // failure: tamper the anchor.log_root
  const t1 = JSON.parse(JSON.stringify(a0)); t1.log_root = '11'.repeat(32);
  ok(verifyAnchored(entries, t1, onchainCommitment(t1), trusted).verified === false, 'tampered anchor.log_root -> FAILS');

  // adversarial: anchor signed by an attacker ledger key
  const evil = createAnchorChain({ ed: ed(9), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) }, { chain: 'qrl-zond' });
  const aEvil = appendAnchor(evil, { root: lv.tip, n: lv.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 4 });
  ok(verifyAnchored(entries, aEvil, onchainCommitment(aEvil), trusted).verified === false, 'adversarial: anchor forged under attacker ledger keys -> FAILS against the pinned authority');
  // adversarial: strip the PQ leg of the anchor signature (downgrade)
  const t2 = JSON.parse(JSON.stringify(a0)); t2.mldsa_sig = '00';
  ok(verifyAnchored(entries, t2, onchainCommitment(t2), trusted).verified === false, 'adversarial: stripped PQ leg on the anchor -> FAILS (anti-downgrade)');
  // adversarial: anchor over a log signed by the WRONG log signer (claims our log_signer but log verifies under attacker)
  ok(verifyAnchored(entries, a0, onchainCommitment(a0), { log: { ed: ed(9).publicKey, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey }, anchor: trustedAnchor }).verified === false, 'wrong pinned LOG signer -> FAILS (log will not verify)');

  // anchor CHAIN: three periodic anchors over a growing log
  const ach = createAnchorChain(anchorSigner, { chain: 'algorand' });
  const lv2 = verifyLog(entries2, trustedLog);
  appendAnchor(ach, { root: lv.tip, n: lv.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 10 });
  appendAnchor(ach, { root: lv2.tip, n: lv2.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 11 });
  appendAnchor(ach, { root: lv2.tip, n: lv2.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 12 });
  ok(verifyAnchorChain(ach.anchors, trustedAnchor).verified === true, 'anchor chain of 3 periodic anchors verifies (linked + dual-signed)');
  const tc = JSON.parse(JSON.stringify(ach.anchors)); tc[1].log_root = '22'.repeat(32);
  ok(verifyAnchorChain(tc, trustedAnchor).verified === false, 'tampered anchor in the chain -> chain verify FAILS');
  const reordered = [ach.anchors[0], ach.anchors[2], ach.anchors[1]];
  ok(verifyAnchorChain(reordered, trustedAnchor).verified === false, 'reordered anchor chain -> FAILS (linkage)');
  ok(verifyAnchorChain(ach.anchors, { ed: ed(9).publicKey, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)).publicKey }).verified === false, 'wrong pinned anchor authority -> chain FAILS');
  // RED-TEAM: tail-truncation + log-state rollback are invisible from a chain alone -> opt-in pins make them detectable
  const fullTip = verifyAnchorChain(ach.anchors, trustedAnchor).tip;
  ok(verifyAnchorChain(ach.anchors, trustedAnchor, { expectedTip: fullTip }).verified === true, 'expectedTip matching the real tip -> verifies');
  const trunc = ach.anchors.slice(0, 2);
  ok(verifyAnchorChain(trunc, trustedAnchor).verified === true, 'a truncated prefix is itself a valid chain (truncation invisible by default — documented)');
  ok(verifyAnchorChain(trunc, trustedAnchor, { expectedTip: fullTip }).verified === false && verifyAnchorChain(trunc, trustedAnchor, { minLength: 3 }).verified === false, 'red-team: tail truncation DETECTED via expectedTip / minLength');
  const ach2 = createAnchorChain(anchorSigner, { chain: 'qrl-zond' });
  appendAnchor(ach2, { root: lv2.tip, n: 5, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 1 });
  appendAnchor(ach2, { root: lv.tip, n: 2, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 2 });
  ok(verifyAnchorChain(ach2.anchors, trustedAnchor).verified === true && verifyAnchorChain(ach2.anchors, trustedAnchor, { requireMonotonicN: true }).verified === false, 'red-team: anchored log-state rollback (n 5->2) DETECTED via requireMonotonicN');

  // sweep-R1 lock: a mid-chain log_signer SWAP (anchor authority validly re-anchors a DIFFERENT log signer) is REJECTED
  const swapAch = createAnchorChain(anchorSigner, { chain: 'algorand' });
  appendAnchor(swapAch, { root: lv.tip, n: lv.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 1 });
  appendAnchor(swapAch, { root: lv2.tip, n: lv2.n, logSignerPubs: { ed: bytesToHex(ed(9).publicKey), mldsa: bytesToHex(ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey) } }, { ts: 2 });
  { const v = verifyAnchorChain(swapAch.anchors, trustedAnchor); ok(v.verified === false && /log_signer/.test(v.reason || ''), 'sweep-R1 lock: mid-chain log_signer swap REJECTED (silent log-key change caught)'); }

  // DUAL-CHAIN: anchor the same log to Algorand + QRL-Zond at once; both must verify + bind the same root
  const dual = createDualAnchor(anchorSigner);
  const da = appendDual(dual, { root: lv.tip, n: lv.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 20 });
  ok(verifyDual(entries, da, trusted).verified === true && verifyDual(entries, da, trusted).dual_bound === true, 'dual-anchor: same log committed to Algorand + QRL-Zond -> both verify + bind the same root');
  ok(da.commitments.algorand && da.commitments['qrl-zond'] && da.commitments.algorand !== da.commitments['qrl-zond'], 'dual-anchor: distinct per-chain on-chain commitments (one per ledger)');
  const dtamper = { primary: JSON.parse(JSON.stringify(da.primary)), secondary: da.secondary }; dtamper.primary.log_root = '33'.repeat(32);
  ok(verifyDual(entries, dtamper, trusted).verified === false, 'dual-anchor: tampering ONE chain anchor -> dual verify FAILS (both must hold)');

  // MORE-PQ-APEX: optional SLH-DSA hash-based 3rd leg on anchors (classical Ed25519 ∧ lattice ML-DSA ∧ hash-based SLH-DSA)
  const aSigner3 = { ed: anchorSigner.ed, mldsa: anchorSigner.mldsa, slh: slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(8)) };
  const tA3 = { log: trustedLog, anchor: { ed: trustedAnchor.ed, mldsa: trustedAnchor.mldsa, slh: aSigner3.slh.publicKey } };
  const ach3 = createAnchorChain(aSigner3, { chain: 'algorand' });
  const an3 = appendAnchor(ach3, { root: lv.tip, n: lv.n, logSignerPubs: { ed: bytesToHex(trustedLog.ed), mldsa: bytesToHex(trustedLog.mldsa) } }, { ts: 30 });
  ok(typeof an3.slh_sig === 'string', '3-leg anchor: carries an SLH-DSA hash-based signature');
  ok(verifyAnchored(entries, an3, onchainCommitment(an3), tA3).verified === true, '3-leg anchor: verifies under classical ∧ lattice ∧ hash-based pinned keys');
  ok(verifyAnchored(entries, an3, onchainCommitment(an3), trusted).verified === true, '3-leg anchor still verifies as 2-leg when slh not pinned (additive / 0-downgrade)');
  const an3strip = JSON.parse(JSON.stringify(an3)); delete an3strip.slh_sig;
  ok(verifyAnchored(entries, an3strip, onchainCommitment(an3strip), tA3).verified === false, '3-leg anchor: stripping the SLH leg FAILS when trustedAnchor.slh is pinned (anti-downgrade)');
  ok(verifyAnchorChain(ach3.anchors, tA3.anchor).verified === true, '3-leg anchor chain verifies under the pinned hash-based authority key');

  // TOTAL: malformed -> fail-closed, never throws
  let total = true;
  for (const bad of [null, undefined, {}, 42, { seq: 0 }]) { try { if (verifyAnchored(entries, bad, '00', trusted).verified !== false) total = false; if (verifyAnchorChain(bad, trustedAnchor).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed anchors -> verified:false, never throws');

  console.log('pqanchor self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqanchor\.mjs$/.test(process.argv[1] || '')) selfTest();
