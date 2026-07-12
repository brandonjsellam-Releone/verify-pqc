/*!
 * qiv — Quantum IP Vault (reference, DRAFT). An immutable, post-quantum-signed intellectual-property INSCRIPTION +
 * PROVENANCE core: hash an IP artifact (patent draft, trade-secret ciphertext, lab notebook, dataset, defensive
 * publication) -> AND-compose a post-quantum signature over its digest + metadata -> bind it to a TRELYAN Vault Cell
 * and a PQ timestamp -> emit the EXACT bytes to anchor on Algorand (TRELYAN's live PQ chain, app 763809096) -> and
 * VERIFY the whole record offline, fail-closed. Plus an append-only, hash-chained, per-transition-signed CHAIN OF
 * CUSTODY (Blueprint-6 Module 2). Composes the audited-composition primitives already in this SDK: pqseal
 * (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519 AND-composition), pqtsa (PQ timestamp token), pqanchor (ledger binding).
 *
 * WHAT THIS IS (precise, falsifiable):
 *  - A tamper-EVIDENT, independently-VERIFIABLE, post-quantum-signed record that a specific artifact (by digest) +
 *    metadata existed and was bound to a Vault Cell at a timestamped moment, anchorable to a public ledger.
 *  - The primary signature is NIST-STANDARDIZED: ML-DSA-87 (FIPS 204) ∧ SLH-DSA-256f (FIPS 205) ∧ Ed25519. A forgery
 *    must break a lattice AND a hash-based AND a classical scheme (family diversity, anti-downgrade — see pqseal).
 *
 * WHAT THIS IS NOT (claim hygiene — do not overclaim):
 *  - NOT "legally admissible." It produces evidence that can SUPPORT an IP dispute (existence-at-time + integrity +
 *    provenance); ADMISSIBILITY and legal weight are determinations for a court + counsel in the relevant jurisdiction.
 *  - NOT a patent filing, examination, or grant. Inscribing a hash does not create, register, or prosecute any IP right.
 *  - NOT "unbreakable / quantum-proof." The claim is the specific composition above, verifiable offline against pinned keys.
 *  - Falcon-1024 is the OPTIONAL on-chain provenance leg only (the AVM `falcon_verify` opcode), and FN-DSA / FIPS 206 is
 *    a DRAFT standard — every Falcon mention is caveated. The off-chain record's integrity does NOT depend on Falcon.
 *  - MARKETPLACE / "fractional ownership / tokenized patent shares" (Blueprint-6 Module 3) is a SECURITIES matter and is
 *    DELIBERATELY NOT IMPLEMENTED here — see `marketplace()`. It requires securities counsel before any build.
 *  - This module is the (UNAUDITED) composition layer; the crypto is @noble/{post-quantum,curves} (independently audited).
 *
 * OWNER-GATED (not done here): actually broadcasting to Algorand (needs a funded account + the on-chain Falcon signer),
 * off-chain storage pinning (IPFS/Arweave/Pinata), and any marketplace/transfer-of-value feature. This core produces the
 * exact post bytes + verifies after the fact, exactly as pqanchor does. Self-test: `node qiv.mjs`.
 */
import { seal, openSeal } from './pqseal.mjs';
import { genTsaKey, timestamp, verifyTimestamp } from './pqtsa.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

// ---------- domain-separated tags (never sign/verify bare bytes — see domain-separation.mjs) ----------
const ARTIFACT_TAG = utf8ToBytes('trelyan-qiv-artifact-v1');   // hashing an IP artifact
const RECORD_TAG   = utf8ToBytes('trelyan-qiv-record-v1');     // hashing an inscription record core
const CUSTODY_TAG  = utf8ToBytes('trelyan-qiv-custody-v1');    // hash-chained custody entry core
const CUSTODY_CTX  = utf8ToBytes('trelyan-qiv-custody-ctx-v1');// signature context for custody entries
const NOTE_MAGIC   = utf8ToBytes('TRLQIV1');                   // Algorand note wire prefix
const GENESIS = '00'.repeat(32);

// ---------- Vault Cell semantics (TRELYAN core: 1,024 Falcon-1024 Vault Cell NFTs on Algorand; #1 = genesis) ----------
export const CELL_MIN = 1, CELL_MAX = 1024;
// Cell lifecycle: sealed (registered/pending) -> inscribed (anchored on-chain) -> released (e.g. patent granted / published).
export const CELL_STATES = ['sealed', 'inscribed', 'released'];
const CELL_ORDER = Object.fromEntries(CELL_STATES.map((s, i) => [s, i]));
// IP artifact categories (Blueprint-6 Module 1).
export const IP_TYPES = ['patent', 'trade_secret', 'research_data', 'prior_art', 'dataset', 'design', 'copyright', 'other'];
// Custody actions (Blueprint-6 Module 2). ASSIGN/LICENSE record provenance ONLY — they move NO value (see securities note).
export const CUSTODY_ACTIONS = ['create', 'inscribe', 'release', 'assign', 'license', 'annotate'];
// The TRELYAN live PQ chain coordinates (reference; broadcasting is owner-gated).
export const ALGORAND = { network: 'testnet', app_id: 763809096, falcon_header: '0xBA', note: 'Falcon-1024 det1024 on-chain leg = DRAFT (FIPS 206 pending)' };

// deterministic sorted-key canonical JSON (RFC-8785 / JCS-style) — identical transform in every module here.
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const toBytes = (x) => (x instanceof Uint8Array ? x : utf8ToBytes(String(x)));

/** digestArtifact(bytes) -> 128-hex SHA-512 (Grover-hardened) of the artifact under the artifact domain tag. */
export function digestArtifact(bytes) {
  return bytesToHex(sha512(concatBytes(ARTIFACT_TAG, toBytes(bytes))));
}

// the signable/verifiable CORE of an inscription record (everything the signature covers; excludes signatures/derived hashes).
function recordCore(r) {
  return {
    v: 'qiv-1', cell_id: r.cell_id, cell_state: r.cell_state, ip_type: r.ip_type,
    artifact_sha512: r.artifact_sha512,
    metadata: r.metadata,                                   // {title, inventors[], jurisdiction, filing_ref?, ...} — caller-supplied
    offchain: r.offchain,                                   // {kind:'ipfs'|'arweave'|'none', uri?, sha256?} — pointer only; NOT pinned here
    created_ts: r.created_ts ?? null,
  };
}
const recordHash = (coreBytes) => bytesToHex(sha256(concatBytes(RECORD_TAG, coreBytes)));

// deterministic Algorand note bytes for this record (what you WOULD post; broadcasting is owner-gated).
//   "TRLQIV1" | app_id(8B) | cell_id(2B) | artifact_sha512(64B) | record_hash(32B)
// Integers are written BIG-ENDIAN / network byte order (DataView's default is big-endian on every platform, but we
// pass `false` EXPLICITLY so the wire encoding is unambiguous to an auditor and cannot drift on a refactor).
function anchorNote(appId, cellId, artifactSha512Hex, recordHashHex) {
  const app = new Uint8Array(8); new DataView(app.buffer).setBigUint64(0, BigInt(appId), false);
  const cell = new Uint8Array(2); new DataView(cell.buffer).setUint16(0, cellId, false);
  const body = concatBytes(NOTE_MAGIC, app, cell, hexToBytes(artifactSha512Hex), hexToBytes(recordHashHex));
  return bytesToHex(body);
}

// off-chain storage pointer is a CONTENT pointer only — never a payment/escrow/marketplace/contract endpoint (securities
// hygiene). ALLOWLIST the storage scheme per kind (a positive list is stronger than a denylist of payment patterns).
const OFFCHAIN_KINDS = ['none', 'ipfs', 'arweave', 'https'];
const OFFCHAIN_SCHEME = { ipfs: /^ipfs:\/\//i, arweave: /^(ar|arweave):\/\//i, https: /^https:\/\//i };
function assertOffchain(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw new Error('qiv: offchain must be an object');
  if (!OFFCHAIN_KINDS.includes(o.kind)) throw new Error('qiv: offchain.kind must be one of ' + OFFCHAIN_KINDS.join(','));
  // kind='none' must be CONGRUENT: no dangling uri/sha256 (sweep R1) — else a signed record could carry a hidden pointer
  // that verifiers ignore, making the signed offchain object internally inconsistent.
  if (o.kind === 'none') { if (o.uri != null || o.sha256 != null) throw new Error('qiv: offchain.kind=none must carry no uri/sha256'); return; }
  if (typeof o.uri !== 'string' || !o.uri) throw new Error('qiv: offchain.uri required for kind ' + o.kind);
  if (!OFFCHAIN_SCHEME[o.kind].test(o.uri)) throw new Error(`qiv: offchain.uri must use the ${o.kind} scheme (a CONTENT pointer only — not a payment/marketplace/contract endpoint)`);
}

function assertCell(cellId) {
  if (!Number.isInteger(cellId) || cellId < CELL_MIN || cellId > CELL_MAX)
    throw new Error(`qiv: cell_id must be an integer in [${CELL_MIN}, ${CELL_MAX}] (1,024 Vault Cell supply)`);
}

/**
 * inscribe({ cellId, ipType, metadata, artifactBytes, offchain?, cellState?, createdTs? }, signers, tsaKey?, opts?)
 *   signers : [{alg,secretKey,publicKey}, ...] for pqseal (recommend ML-DSA-87 + SLH-DSA-256f + Ed25519 = full family diversity)
 *   tsaKey  : { secretKey, publicKey } ML-DSA-87 TSA keypair (from genTsaKey). If omitted, no timestamp token is attached.
 * Returns a self-contained Inscription Record { record, seal, tst?, anchor, produced_by }.
 */
export function inscribe({ cellId, ipType, metadata, artifactBytes, offchain, cellState, createdTs }, signers, tsaKey, opts = {}) {
  assertCell(cellId);
  if (!IP_TYPES.includes(ipType)) throw new Error('qiv: unknown ip_type: ' + ipType + ' (allowed: ' + IP_TYPES.join(',') + ')');
  if (!Array.isArray(signers) || !signers.length) throw new Error('qiv: need >=1 pqseal signer (recommend 3-family)');
  const state = cellState ?? 'sealed';
  if (!CELL_STATES.includes(state)) throw new Error('qiv: unknown cell_state: ' + state);
  const oc = offchain ?? { kind: 'none' };
  assertOffchain(oc);
  const artifact_sha512 = digestArtifact(artifactBytes);
  const record = recordCore({
    cell_id: cellId, cell_state: state, ip_type: ipType, artifact_sha512,
    metadata: metadata ?? {}, offchain: oc, created_ts: createdTs ?? (opts.ts ?? null),
  });
  const recordBytes = utf8ToBytes(canon(record));
  const rHash = recordHash(recordBytes);
  // primary signature: AND-composition over the record core (pqseal binds suite + all leg pubkeys + payload hash).
  const sealEnv = seal(recordBytes, signers);
  // PQ timestamp over the artifact digest (existence-at-time), optional.
  let tst = null;
  if (tsaKey && tsaKey.secretKey && tsaKey.publicKey) {
    tst = timestamp({ content_sha256: artifact_sha512, serial: rHash.slice(0, 16), policy: 'trelyan-qiv-baseline' }, tsaKey.secretKey, tsaKey.publicKey, { ts: opts.ts });
  }
  const appId = opts.appId ?? ALGORAND.app_id;
  const note = anchorNote(appId, cellId, artifact_sha512, rHash);
  return {
    record, record_hash: rHash, seal: sealEnv, tst,
    anchor: {
      chain: 'algorand', network: opts.network ?? ALGORAND.network, app_id: appId,
      note_hex: note, commitment: rHash,
      on_chain_signature: 'falcon-1024-det1024 (OWNER-GATED; DRAFT FIPS 206) — not produced here',
      broadcast: false,   // never broadcasts; produces the exact bytes only (see pqanchor honesty)
    },
    produced_by: 'qiv.mjs (reference, DRAFT)',
  };
}

/**
 * verifyInscription(inscription, artifactBytes, opts?) — TOTAL / fail-closed.
 *   opts.trusted = { 'ML-DSA-87': pubBytes, ... }  pin pqseal legs (per-family)
 *   opts.requireKinds = ['lattice','hash-based','classical']  require full family diversity (recommended)
 *   opts.tsaPub = Uint8Array  pin the TSA key (required to trust the timestamp, else it's only self-consistent)
 *   opts.appId  = number      assert the anchor targets this app id
 * Returns { verified, artifactOk, sealOk, tstOk, anchorOk, cellOk, detail }.
 */
export function verifyInscription(inscription, artifactBytes, opts = {}) {
  const fail = (reason, extra = {}) => ({ verified: false, artifactOk: false, sealOk: false, tstOk: false, anchorOk: false, cellOk: false, reason, ...extra });
  try {
    if (!inscription || typeof inscription !== 'object' || !inscription.record || !inscription.seal) return fail('shape');
    const r = inscription.record;
    if (!r || typeof r !== 'object' || Array.isArray(r)) return fail('record shape');
    // EXACT-key schema check: the record must carry precisely the signed fields — no missing (which recordCore would
    // then reconstruct from `undefined`) and no EXTRA unsigned keys (which the seal wouldn't cover but a naive consumer
    // might read + trust). This closes the unsigned-field-injection gap independently of the signature check.
    const EXPECTED = ['artifact_sha512', 'cell_id', 'cell_state', 'created_ts', 'ip_type', 'metadata', 'offchain', 'v'];
    const rk = Object.keys(r).sort();
    if (rk.length !== EXPECTED.length || rk.some((k, i) => k !== EXPECTED[i])) return fail('record-schema (missing/extra field)');
    if (r.v !== 'qiv-1') return fail('record version');
    // sweep R2: re-run offchain well-formedness at VERIFY time (not only at inscribe) — reject an incongruent signed
    // record (e.g. kind='none' carrying a dangling uri/sha256) regardless of a valid signature (defense-in-depth).
    try { assertOffchain(r.offchain); } catch { return fail('offchain incongruent'); }
    // cell + type + state sanity
    const cellOk = Number.isInteger(r.cell_id) && r.cell_id >= CELL_MIN && r.cell_id <= CELL_MAX
      && IP_TYPES.includes(r.ip_type) && CELL_STATES.includes(r.cell_state);
    // recompute the artifact digest from the supplied bytes and check it matches the record
    const artifact_sha512 = digestArtifact(artifactBytes);
    const artifactOk = artifact_sha512 === r.artifact_sha512;
    // recompute the record core bytes + hash (defends against a doctored record vs its signature/anchor)
    const recordBytes = utf8ToBytes(canon(recordCore(r)));
    const rHash = recordHash(recordBytes);
    const recordHashOk = rHash === inscription.record_hash;
    // verify the pqseal AND-composition over the record core
    const sealRes = openSeal(recordBytes, inscription.seal, {
      trusted: opts.trusted, requireKinds: opts.requireKinds, requirePinned: opts.requirePinned,
      minLegs: opts.minLegs, requireDistinctLegs: opts.requireDistinctLegs !== false,
    });
    const sealOk = sealRes.verified;
    // verify the timestamp token if present (pinned TSA => authenticity; unpinned => self-consistent only)
    let tstOk = true, tstDetail = 'no-tst';
    if (inscription.tst) {
      const tv = verifyTimestamp(inscription.tst, opts.tsaPub);
      // the token must attest THIS artifact digest
      const bindsArtifact = tv.claims && tv.claims.content_sha256 === r.artifact_sha512;
      tstOk = tv.verified && bindsArtifact;
      tstDetail = tstOk ? (tv.pinned ? 'tst ok (pinned)' : 'tst self-consistent (UNPINNED — supply opts.tsaPub to trust)') : 'tst invalid or does not bind artifact';
    }
    // re-derive the anchor note from the record and check it matches (determinism / no swapped anchor)
    const appId = opts.appId ?? (inscription.anchor && inscription.anchor.app_id) ?? ALGORAND.app_id;
    const expectNote = anchorNote(appId, r.cell_id, r.artifact_sha512, rHash);
    const anchorOk = !!inscription.anchor && inscription.anchor.note_hex === expectNote
      && inscription.anchor.commitment === rHash && inscription.anchor.broadcast === false;
    const verified = !!(cellOk && artifactOk && recordHashOk && sealOk && tstOk && anchorOk);
    return {
      verified, cellOk, artifactOk, recordHashOk, sealOk, tstOk, anchorOk,
      seal: { suiteMatch: sealRes.suiteMatch, kinds: sealRes.kinds, fullyAnchored: sealRes.fullyAnchored, distinctLegs: sealRes.distinctLegs },
      tst: tstDetail,
      reason: verified ? 'ok' : [!cellOk && 'cell/type/state', !artifactOk && 'artifact-digest', !recordHashOk && 'record-hash', !sealOk && 'seal', !tstOk && 'tst', !anchorOk && 'anchor'].filter(Boolean).join(','),
    };
  } catch { return fail('exception'); }
}

/* ============================ Module 2: CHAIN OF CUSTODY (append-only, hash-chained, AND-composition) ============================
 * Mirrors pqauditlog's proven pattern (Ed25519 ∧ ML-DSA-87 ∧ optional SLH-DSA-256f, prev_hash linkage, nonce anti-replay,
 * non-decreasing ts) but with QIV-native actions/states. A high-value transfer (assign) SHOULD require multi-sig — modeled
 * as N independent custody logs / co-signatures by the caller; this reference enforces single-signer chain integrity.
 */
function custodyCore(e) {
  return { v: 'qivc-1', seq: e.seq, ts: e.ts, nonce: e.nonce, cell_id: e.cell_id, actor: e.actor, action: e.action, cell_state: e.cell_state, ref_sha256: e.ref_sha256, prev_hash: e.prev_hash };
}
const custodyHash = (coreBytes) => bytesToHex(sha256(concatBytes(CUSTODY_TAG, coreBytes)));
const refHash = (p) => bytesToHex(sha256(concatBytes(CUSTODY_TAG, toBytes(p ?? ''))));

/** openCustody(cellId, signer) — signer = { ed:{secretKey,publicKey}, mldsa:{secretKey,publicKey}, slh?:{...} }. */
export function openCustody(cellId, signer) {
  assertCell(cellId);
  if (!signer || !signer.ed || !signer.mldsa) throw new Error('qiv: custody signer must be { ed, mldsa } keypairs');
  const signer_pub = { ed: bytesToHex(signer.ed.publicKey), mldsa: bytesToHex(signer.mldsa.publicKey) };
  if (signer.slh) signer_pub.slh = bytesToHex(signer.slh.publicKey);
  return { cell_id: cellId, entries: [], seen: new Set(), signer, signer_pub };
}

/** appendCustody(log, { actor, action, cellState, payload?, ts?, nonce? }) -> the new signed entry. */
export function appendCustody(log, rec) {
  const last = log.entries[log.entries.length - 1];
  const seq = log.entries.length;
  const ts = rec.ts ?? (last ? last.ts : 0);
  if (!Number.isFinite(ts)) throw new Error('ts must be finite');
  if (last && ts < last.ts) throw new Error('ts must be non-decreasing');
  if (!CUSTODY_ACTIONS.includes(rec.action)) throw new Error('qiv: unknown custody action: ' + rec.action);
  if (!CELL_STATES.includes(rec.cellState)) throw new Error('qiv: unknown cell_state: ' + rec.cellState);
  // enforce monotonic (non-regressing) cell state across the custody chain
  if (last && CELL_ORDER[rec.cellState] < CELL_ORDER[last.cell_state]) throw new Error(`qiv: cell_state cannot regress (${last.cell_state} -> ${rec.cellState})`);
  const nonce = rec.nonce ?? bytesToHex(randomBytes(16));
  if (log.seen.has(nonce)) throw new Error('qiv: nonce reuse (replay): ' + nonce);
  const core = custodyCore({ seq, ts, nonce, cell_id: log.cell_id, actor: rec.actor, action: rec.action, cell_state: rec.cellState, ref_sha256: refHash(rec.payload), prev_hash: last ? last.entry_hash : GENESIS });
  const coreBytes = utf8ToBytes(canon(core));
  // Domain separation via CUSTODY_CTX: Ed25519 has no native `context` arg in this @noble build, so the context is
  // PREPENDED to the message (concatBytes) — mechanically the same separation ML-DSA gets via its `{context}` option.
  // This is the identical house pattern used in pqseal.mjs (FAMILIES) + pqauditlog.mjs; verify (verifyCustody) mirrors it.
  const entry = { ...core,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(CUSTODY_CTX, coreBytes), log.signer.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, log.signer.mldsa.secretKey, { context: CUSTODY_CTX })),
    entry_hash: custodyHash(coreBytes) };
  if (log.signer.slh) entry.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, log.signer.slh.secretKey, { context: CUSTODY_CTX }));
  log.seen.add(nonce); log.entries.push(entry);
  return entry;
}

/** verifyCustody(entries, trusted) — TOTAL / fail-closed. trusted = { ed, mldsa, slh? } (Uint8Array pubkeys). */
export function verifyCustody(entries, trusted) {
  const base = { verified: false, n: 0, broken_at: 0, reason: '' };
  try {
    if (!Array.isArray(entries)) return { ...base, reason: 'entries not an array' };
    if (!trusted || !trusted.ed || !trusted.mldsa) return { ...base, reason: 'no pinned signer keys (authenticity uncheckable)' };
    const seen = new Set(); let prev = GENESIS; let lastTs = -Infinity; let lastState = -1; let cellId = null;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i]; const at = (reason) => ({ ...base, n: entries.length, broken_at: i, reason });
      if (!e || typeof e !== 'object' || e.seq !== i) return at('seq/shape');
      if (cellId === null) cellId = e.cell_id; else if (e.cell_id !== cellId) return at('cell_id changed mid-chain');
      const coreBytes = utf8ToBytes(canon(custodyCore(e)));
      if (e.prev_hash !== prev) return at('chain linkage (prev_hash)');
      if (custodyHash(coreBytes) !== e.entry_hash) return at('entry_hash mismatch (tamper)');
      if (!CUSTODY_ACTIONS.includes(e.action)) return at('unknown action');
      if (!CELL_STATES.includes(e.cell_state)) return at('unknown cell_state');
      if (CELL_ORDER[e.cell_state] < lastState) return at('cell_state regressed (rollback)');
      if (typeof e.ts !== 'number' || !Number.isFinite(e.ts) || e.ts < lastTs) return at('ts not finite/non-decreasing (back-dating)');
      if (seen.has(e.nonce)) return at('nonce replay');
      let edOk = false, pqOk = false;
      try { edOk = ed25519.verify(hexToBytes(e.ed_sig), concatBytes(CUSTODY_CTX, coreBytes), trusted.ed); } catch { edOk = false; }
      try { pqOk = ml_dsa87.verify(hexToBytes(e.mldsa_sig), coreBytes, trusted.mldsa, { context: CUSTODY_CTX }); } catch { pqOk = false; }
      if (!edOk) return at('Ed25519 signature invalid');
      if (!pqOk) return at('ML-DSA-87 signature invalid (or PQ leg stripped)');
      if (trusted.slh) {
        let slhOk = false;
        try { slhOk = !!(e.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(e.slh_sig), coreBytes, trusted.slh, { context: CUSTODY_CTX })); } catch { slhOk = false; }
        if (!slhOk) return at('SLH-DSA hash-based leg invalid/missing (required when trusted.slh pinned)');
      }
      seen.add(e.nonce); prev = e.entry_hash; lastTs = e.ts; lastState = CELL_ORDER[e.cell_state];
    }
    return { verified: true, n: entries.length, broken_at: -1, reason: 'ok', cell_id: cellId, tip: entries.length ? entries[entries.length - 1].entry_hash : GENESIS, final_state: entries.length ? entries[entries.length - 1].cell_state : null };
  } catch { return base; }
}

/* ============================ Module 3: MARKETPLACE — SECURITIES-GATED (deliberately NOT implemented) ============================ */
/** marketplace() — Blueprint-6 Module 3 (buy/sell/license, "fractional ownership / tokenized patent shares") describes the
 *  offer/sale of investment interests, which is a SECURITIES matter (e.g. US Securities Act, EU Prospectus/MiCA, CH FINMA).
 *  Building it without securities counsel + a compliant structure is a legal red-line. This function exists to make the gate
 *  explicit and machine-enforced: it always throws. Provenance-only "assign"/"license" custody entries (which move NO value
 *  and confer NO investment interest) live in the custody chain above and are permitted. */
export function marketplace() {
  throw new Error('QIV_MARKETPLACE_SECURITIES_GATED: Blueprint-6 Module 3 (fractional/tokenized IP ownership, sale/licensing of value) is a securities matter and is not implemented. Requires securities counsel + a compliant offering structure before any build. Provenance-only custody (assign/license, no value transfer) is available via appendCustody().');
}

/* ---------------------------------------- self-test: node qiv.mjs ---------------------------------------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n, len = 32) => new Uint8Array(len).fill(n);
  const mkEd = (n) => { const sk = seed(n); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  const mkMl = (n) => ml_dsa87.keygen(seed(n));
  const mkSlh = (n) => slh_dsa_sha2_256f.keygen(seed(n, 96));
  // three-family signer set for pqseal
  const A = { alg: 'ML-DSA-87', ...mkMl(11) };
  const B = { alg: 'SLH-DSA-256f', ...mkSlh(22) };
  const C = { alg: 'Ed25519', ...mkEd(33) };
  const signers = [A, B, C];
  const trusted = { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey, 'Ed25519': C.publicKey };
  const tsa = genTsaKey(seed(44));
  const artifact = utf8ToBytes('PATENT DRAFT: Method and apparatus for lattice-based key encapsulation. Claims 1-20. Figs 1-7.');

  // 1. inscribe
  const ins = inscribe({ cellId: 7, ipType: 'patent', metadata: { title: 'ML-KEM apparatus', inventors: ['B. Sellam'], jurisdiction: 'US' }, artifactBytes: artifact, offchain: { kind: 'ipfs', uri: 'ipfs://bafyPLACEHOLDER' } }, signers, { secretKey: tsa.secretKey, publicKey: tsa.publicKey }, { ts: 1_700_000_000 });
  ok(ins.record.cell_id === 7 && ins.record.cell_state === 'sealed', 'inscribe: cell + state');
  ok(ins.anchor.broadcast === false && ins.anchor.note_hex.startsWith(bytesToHex(NOTE_MAGIC)), 'inscribe: anchor note built, not broadcast');
  ok(!!ins.tst && ins.tst.content_sha256 === ins.record.artifact_sha512, 'inscribe: tst binds artifact digest');

  // 2. verify (full family diversity + pinned + pinned TSA)
  const v = verifyInscription(ins, artifact, { trusted, requireKinds: ['lattice', 'hash-based', 'classical'], tsaPub: tsa.publicKey, appId: ALGORAND.app_id });
  ok(v.verified, 'verify: honest record verifies (pinned, 3-family, TSA)');
  ok(v.seal.kinds.length === 3, 'verify: 3 distinct families present');

  // 3. tamper the artifact -> must fail
  ok(!verifyInscription(ins, utf8ToBytes('DIFFERENT artifact'), { trusted }).verified, 'verify: wrong artifact rejected');

  // 4. tamper the record metadata -> seal + record-hash must fail
  const tampered = JSON.parse(JSON.stringify(ins)); tampered.record.metadata.title = 'STOLEN TITLE';
  ok(!verifyInscription(tampered, artifact, { trusted }).verified, 'verify: doctored metadata rejected');

  // 5. swap the anchor note -> must fail
  const swapped = JSON.parse(JSON.stringify(ins)); swapped.anchor.note_hex = swapped.anchor.note_hex.slice(0, -2) + (swapped.anchor.note_hex.endsWith('00') ? '01' : '00');
  ok(!verifyInscription(swapped, artifact, { trusted }).anchorOk, 'verify: tampered anchor note rejected');

  // 6. drop the SLH (hash-based) leg -> requireKinds must fail (anti-downgrade)
  const dropped = JSON.parse(JSON.stringify(ins)); dropped.seal.legs = dropped.seal.legs.filter((l) => l.alg !== 'SLH-DSA-256f'); dropped.seal.suite = 'trelyan-seal/ML-DSA-87+Ed25519';
  ok(!verifyInscription(dropped, artifact, { trusted, requireKinds: ['lattice', 'hash-based', 'classical'] }).verified, 'verify: dropped hash-based leg rejected (downgrade)');

  // 7. cell bounds
  let threw = false; try { inscribe({ cellId: 1025, ipType: 'patent', metadata: {}, artifactBytes: artifact }, signers); } catch { threw = true; }
  ok(threw, 'inscribe: cell_id > 1024 rejected');

  // 7b. TST that attests a DIFFERENT artifact digest must fail (binding enforced even when TSA unpinned)
  const badTst = JSON.parse(JSON.stringify(ins)); badTst.tst.content_sha256 = '00'.repeat(64);
  ok(!verifyInscription(badTst, artifact, { trusted }).verified, 'verify: TST over wrong digest rejected (unpinned)');
  ok(!verifyInscription(badTst, artifact, { trusted, tsaPub: tsa.publicKey }).verified, 'verify: TST over wrong digest rejected (pinned)');

  // 7c. injecting an EXTRA unsigned field into the record must be rejected by the schema check
  const injected = JSON.parse(JSON.stringify(ins)); injected.record.evil = 'unsigned-payload';
  ok(!verifyInscription(injected, artifact, { trusted }).verified, 'verify: extra unsigned record field rejected');
  const missing = JSON.parse(JSON.stringify(ins)); delete missing.record.offchain;
  ok(!verifyInscription(missing, artifact, { trusted }).verified, 'verify: missing signed record field rejected');

  // 7d. offchain pointer allowlist: a payment/marketplace-looking URI is refused at inscribe time
  let ocThrew = false; try { inscribe({ cellId: 8, ipType: 'patent', metadata: {}, artifactBytes: artifact, offchain: { kind: 'ipfs', uri: 'https://opensea.io/marketplace/sale/0xdead' } }, signers); } catch { ocThrew = true; }
  ok(ocThrew, 'inscribe: non-ipfs URI under kind:ipfs rejected (content-pointer-only guardrail)');
  ok(inscribe({ cellId: 8, ipType: 'patent', metadata: {}, artifactBytes: artifact, offchain: { kind: 'arweave', uri: 'ar://abcDEF' } }, signers).record.offchain.kind === 'arweave', 'inscribe: valid ar:// pointer accepted');
  ok((() => { try { inscribe({ cellId: 8, ipType: 'patent', metadata: {}, artifactBytes: artifact, offchain: { kind: 'none', uri: 'ipfs://sneaky', sha256: 'ab'.repeat(32) } }, signers); return false; } catch { return true; } })(), 'sweep-R1 lock: offchain kind:none carrying a dangling uri/sha256 REJECTED at inscribe (congruent signed record)');

  // 8. custody chain: create -> inscribe -> release, verifies; regression + tamper rejected
  const cSigner = { ed: mkEd(51), mldsa: mkMl(52), slh: mkSlh(53) };
  const cTrust = { ed: cSigner.ed.publicKey, mldsa: cSigner.mldsa.publicKey, slh: cSigner.slh.publicKey };
  const log = openCustody(7, cSigner);
  appendCustody(log, { actor: 'inventor:BS', action: 'create', cellState: 'sealed', payload: 'draft v1', ts: 1_700_000_000 });
  appendCustody(log, { actor: 'vault', action: 'inscribe', cellState: 'inscribed', payload: 'anchored', ts: 1_700_000_100 });
  appendCustody(log, { actor: 'uspto', action: 'release', cellState: 'released', payload: 'granted', ts: 1_700_000_200 });
  const cv = verifyCustody(log.entries, cTrust);
  ok(cv.verified && cv.final_state === 'released' && cv.n === 3, 'custody: 3-entry chain verifies to released');
  // regression is refused at append time
  let regThrew = false; try { appendCustody(log, { actor: 'x', action: 'annotate', cellState: 'sealed', ts: 1_700_000_300 }); } catch { regThrew = true; }
  ok(regThrew, 'custody: state regression refused');
  // tamper an entry -> verify fails
  const badEntries = JSON.parse(JSON.stringify(log.entries)); badEntries[1].actor = 'attacker';
  ok(!verifyCustody(badEntries, cTrust).verified, 'custody: tampered entry rejected');
  // unpinned custody -> fail-closed
  ok(!verifyCustody(log.entries, {}).verified, 'custody: unpinned verify fails closed');

  // 9. securities gate is machine-enforced
  let gated = false; try { marketplace(); } catch (e) { gated = /SECURITIES_GATED/.test(e.message); }
  ok(gated, 'marketplace: securities gate throws');

  console.log(`\nqiv self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

// ESM "run directly" guard
import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
