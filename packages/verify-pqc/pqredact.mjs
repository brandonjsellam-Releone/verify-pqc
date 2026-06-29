/*!
 * pqredact — post-quantum REDACTABLE / selective-disclosure signed documents (reference, DRAFT). Council R&D pick
 * (11-seat: Moonshot "PQ-RSEP" + the selective-disclosure / data-minimisation theme; watsonx regulatory lens).
 *
 * Sign a document ONCE as a Merkle tree of SALTED field-commitments, with the root signed by ML-DSA-87 (FIPS-204) and
 * an OPTIONAL additive SLH-DSA-SHA2-256f (FIPS-205) hybrid leg. Later, disclose only a SUBSET of fields to a verifier
 * while PROVING the disclosed fields were in the originally-signed document — and the undisclosed fields leak nothing.
 * It compounds the paid Migration Evidence Pack: hand an auditor only their scope, a regulator only the crosswalk, a
 * customer only their findings — each cryptographically bound to the SAME signed original (DORA / eIDAS data-minimisation).
 *
 * NOVEL FALSIFIABLE PROPERTY (what a third party can now verify that they could not before): given a redacted view +
 * the signer's PINNED public key, anyone can (1) recompute the signed Merkle root from ONLY the disclosed leaves + their
 * authentication paths and (2) verify the ML-DSA-87 signature over that root — proving every disclosed field was present,
 * unaltered, in the one signed document. A fabricated or edited disclosed field cannot reproduce the root (2nd-preimage
 * resistance + domain-separated leaf/node tags); an UNDISCLOSED field's value is not recoverable from the sibling hashes
 * (each leaf carries a fresh 16-byte salt, so even a 1-bit field is not brute-forceable). HONEST: this proves presence +
 * integrity + authenticity of disclosed fields and hiding of the rest — it does NOT prove the document is COMPLETE
 * (a signer could omit a field at signing time); completeness needs the signed `keys`/`n` list, which is checked here.
 *
 * Dependency-light: @noble/post-quantum (ml-dsa-87, slh-dsa) + @noble/hashes (sha256). Self-test: node pqredact.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

const REDACT_CTX = utf8ToBytes('trelyan-redactable-doc-v1');           // ML-DSA signing context (domain separation)
const REDACT_SLH_CTX = utf8ToBytes('trelyan-redactable-doc-slh-v1');   // distinct context for the SLH-DSA leg
const LEAF_TAG = utf8ToBytes('trelyan-redact-leaf-v1');                // domain tag for leaf hashes
const NODE_TAG = utf8ToBytes('trelyan-redact-node-v1');                // distinct tag for internal nodes (2nd-preimage)

// canonical JSON (sorted keys) — injective preimage for the values we commit to + the signed core.
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
// big-endian uint32 length-prefix — keeps concatenations injective (a shifted field boundary can never collide).
function lp(b) { const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, b.length, false); return concatBytes(n, b); }
// salted, domain-separated leaf commitment: hides the value (16-byte salt) + binds (key, value).
function leafHash(key, value, saltHex) {
  return sha256(concatBytes(LEAF_TAG, lp(utf8ToBytes(String(key))), lp(utf8ToBytes(canon(value))), lp(hexToBytes(saltHex))));
}
const nodeHash = (l, r) => sha256(concatBytes(NODE_TAG, l, r)); // l,r: Uint8Array digests

// Merkle tree over an ordered list of leaf digests; duplicate-last on odd. Returns root + per-leaf authentication path.
function buildTree(leaves) {
  if (!leaves.length) throw new Error('no leaves');
  const layers = [leaves.slice()];
  while (layers[layers.length - 1].length > 1) {
    const cur = layers[layers.length - 1]; const next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(nodeHash(cur[i], i + 1 < cur.length ? cur[i + 1] : cur[i]));
    layers.push(next);
  }
  const path = (idx) => {
    const sibs = []; let i = idx;
    for (let lvl = 0; lvl < layers.length - 1; lvl++) {
      const cur = layers[lvl];
      const right = i % 2 === 1;
      const sibIdx = right ? i - 1 : (i + 1 < cur.length ? i + 1 : i); // duplicate self if no right sibling
      sibs.push({ sib: bytesToHex(cur[sibIdx]), dir: right ? 'L' : 'R' }); // dir = side the SIBLING sits on
      i = Math.floor(i / 2);
    }
    return sibs;
  };
  return { root: layers[layers.length - 1][0], path };
}
// recompute a root from a leaf digest + its authentication path
function rootFromPath(leaf, path) {
  let h = leaf;
  for (const p of path) { const sib = hexToBytes(p.sib); h = p.dir === 'L' ? nodeHash(sib, h) : nodeHash(h, sib); }
  return h;
}

// fields: ordered [{ key, value }]. opts.slh = an SLH-DSA keypair {secretKey, publicKey} for the hybrid leg; opts.ctx = a
// caller domain string folded into the signed core. Returns { doc (publishable core+sig), fields, salts } — the HOLDER
// keeps fields+salts; only `doc` + a per-disclosure subset ever leave.
export function buildRedactable(fields, signerSk, signerPub, opts = {}) {
  if (!Array.isArray(fields) || !fields.length) throw new Error('fields must be a non-empty array');
  const salts = fields.map(() => bytesToHex(randomBytes(16)));
  const leaves = fields.map((f, i) => leafHash(f.key, f.value, salts[i]));
  const { root } = buildTree(leaves);
  const core = { v: '1', ctx: opts.ctx ?? null, n: fields.length, keys: fields.map((f) => String(f.key)), root: bytesToHex(root) };
  const coreBytes = utf8ToBytes(canon(core));
  const doc = { ...core, signer_pub: bytesToHex(signerPub), sig: bytesToHex(ml_dsa87.sign(coreBytes, signerSk, { context: REDACT_CTX })) };
  if (opts.slh) doc.slh = { signer_pub: bytesToHex(opts.slh.publicKey), sig: bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, opts.slh.secretKey, { context: REDACT_SLH_CTX })) };
  return { doc, fields, salts };
}

// produce a redacted disclosure revealing ONLY discloseKeys (a Set/array of keys). Hidden fields never appear (their
// leaf digests appear only as opaque salted siblings inside the disclosed fields' paths).
export function redact(full, discloseKeys) {
  const want = new Set([...(discloseKeys instanceof Set ? discloseKeys : discloseKeys || [])].map(String));
  const leaves = full.fields.map((f, i) => leafHash(f.key, f.value, full.salts[i]));
  const tree = buildTree(leaves);
  const disclosed = [];
  full.fields.forEach((f, i) => { if (want.has(String(f.key))) disclosed.push({ index: i, key: String(f.key), value: f.value, salt: full.salts[i], path: tree.path(i) }); });
  return { doc: full.doc, disclosed };
}

// TOTAL / fail-closed consumer verification. trustedSignerPub: PIN it for authenticity (else trust-on-first-use against
// the embedded signer_pub). opts.requirePinned / opts.requireHybrid tighten the gate.
export function verifyRedacted(disclosure, trustedSignerPub, opts = {}) {
  try {
    if (!disclosure || typeof disclosure !== 'object' || !disclosure.doc || !Array.isArray(disclosure.disclosed)) return fail();
    const d = disclosure.doc;
    if (typeof d.root !== 'string' || !Array.isArray(d.keys) || typeof d.n !== 'number') return fail();
    const core = { v: d.v, ctx: d.ctx ?? null, n: d.n, keys: d.keys, root: d.root };
    const coreBytes = utf8ToBytes(canon(core));
    const pinned = !!trustedSignerPub && String(d.signer_pub).toLowerCase() === bytesToHex(trustedSignerPub).toLowerCase();
    if (trustedSignerPub && !pinned) return fail();
    let sigOk = false;
    try { sigOk = ml_dsa87.verify(hexToBytes(d.sig), coreBytes, trustedSignerPub ? trustedSignerPub : hexToBytes(d.signer_pub), { context: REDACT_CTX }); } catch { sigOk = false; }
    let slhOk = true;
    if (opts.requireHybrid || (opts.trustedSlhPub && d.slh)) {
      slhOk = false;
      try {
        const pub = opts.trustedSlhPub ? opts.trustedSlhPub : (d.slh ? hexToBytes(d.slh.signer_pub) : null);
        if (opts.trustedSlhPub && d.slh && String(d.slh.signer_pub).toLowerCase() !== bytesToHex(opts.trustedSlhPub).toLowerCase()) slhOk = false;
        else if (d.slh && pub) slhOk = slh_dsa_sha2_256f.verify(hexToBytes(d.slh.sig), coreBytes, pub, { context: REDACT_SLH_CTX });
      } catch { slhOk = false; }
    }
    // every disclosed field must (a) sit at its claimed index in the signed key list and (b) recompute to the signed root
    let rootOk = true; const out = {};
    for (const item of disclosure.disclosed) {
      if (!item || typeof item.index !== 'number' || d.keys[item.index] !== String(item.key) || !Array.isArray(item.path)) { rootOk = false; break; }
      const leaf = leafHash(item.key, item.value, item.salt);
      if (bytesToHex(rootFromPath(leaf, item.path)) !== d.root) { rootOk = false; break; }
      out[item.key] = item.value;
    }
    const verified = sigOk && rootOk && slhOk && (!opts.requirePinned || pinned);
    return { verified, sigOk, rootOk, slhOk, pinned, disclosed: out, root: d.root, signed_keys: d.keys, n: d.n };
  } catch { return fail(); }
}
function fail() { return { verified: false, sigOk: false, rootOk: false, slhOk: false, pinned: false, disclosed: {}, root: null }; }

/* ---------- self-test: node pqredact.mjs ---------- */
function selfTest() {
  let pass = 0, fail2 = 0; const ok = (c, m) => { if (c) pass++; else { fail2++; console.error('FAIL:', m); } };
  const signer = ml_dsa87.keygen(new Uint8Array(32).fill(7));
  const FIELDS = [
    { key: 'org', value: 'ACME Bank' }, { key: 'scope', value: 'TLS + signing' }, { key: 'grade', value: 'C' },
    { key: 'rsa_findings', value: 12 }, { key: 'internal_note', value: 'pen-test creds in vault X' }, { key: 'pq_ready', value: false },
  ];
  const full = buildRedactable(FIELDS, signer.secretKey, signer.publicKey, { ctx: 'evidence-pack-42' });

  // 1. disclose a subset -> verifies, reveals only those fields
  const view = redact(full, ['org', 'grade']);
  const v = verifyRedacted(view, signer.publicKey);
  ok(v.verified && v.disclosed.org === 'ACME Bank' && v.disclosed.grade === 'C', 'subset discloses + verifies under the pinned signer');
  ok(!('internal_note' in v.disclosed) && !('rsa_findings' in v.disclosed), 'undisclosed fields are NOT present in the disclosure');
  // hiding: the secret value never appears anywhere in the serialized disclosure
  ok(!JSON.stringify(view).includes('pen-test creds'), 'hidden field VALUE never appears in the redacted view (salted commitment)');

  // 2. presence/integrity: tamper a disclosed value -> root recompute fails
  const tampered = JSON.parse(JSON.stringify(view)); tampered.disclosed.find((x) => x.key === 'grade').value = 'A';
  ok(verifyRedacted(tampered, signer.publicKey).verified === false, 'tampered disclosed value (grade C->A) -> verify FAILS (root mismatch)');

  // 3. fabricate a field that was never in the signed doc -> fails (no path to the signed root + key/index mismatch)
  const forged = JSON.parse(JSON.stringify(redact(full, ['org'])));
  forged.disclosed.push({ index: 99, key: 'grade', value: 'A', salt: bytesToHex(new Uint8Array(16)), path: forged.disclosed[0].path });
  ok(verifyRedacted(forged, signer.publicKey).verified === false, 'fabricated field (not in signed keys) -> verify FAILS');

  // 4. wrong signer pin -> fails; unpinned (TOFU) still validates the embedded key
  ok(verifyRedacted(view, ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey).verified === false, 'wrong pinned signer key -> verify FAILS');
  ok(verifyRedacted(view, undefined).verified === true && verifyRedacted(view, undefined).pinned === false, 'unpinned verify works (TOFU) but reports pinned:false (validity != trust)');
  ok(verifyRedacted(view, signer.publicKey, { requirePinned: true }).verified === true, 'requirePinned satisfied with the pinned key');

  // 5. disclose-all and disclose-none both verify; disclose-none binds only the signature/root
  ok(verifyRedacted(redact(full, FIELDS.map((f) => f.key)), signer.publicKey).verified === true && Object.keys(verifyRedacted(redact(full, FIELDS.map((f) => f.key)), signer.publicKey).disclosed).length === 6, 'disclose-all verifies with all 6 fields');
  ok(verifyRedacted(redact(full, []), signer.publicKey).verified === true, 'disclose-none verifies (signature + key list only)');

  // 6. hybrid SLH-DSA leg: build with it, require it
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(11));
  const hyFull = buildRedactable(FIELDS, signer.secretKey, signer.publicKey, { slh });
  const hyView = redact(hyFull, ['org', 'pq_ready']);
  ok(verifyRedacted(hyView, signer.publicKey, { requireHybrid: true, trustedSlhPub: slh.publicKey }).verified === true, 'hybrid ML-DSA ∧ SLH-DSA disclosure verifies under both pinned keys');
  ok(verifyRedacted(hyView, signer.publicKey, { requireHybrid: true, trustedSlhPub: slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(2)).publicKey }).verified === false, 'wrong pinned SLH key -> verify FAILS');
  ok(verifyRedacted(redact(full, ['org']), signer.publicKey, { requireHybrid: true }).verified === false, 'requireHybrid on a non-hybrid doc -> verify FAILS');

  // 7. TOTAL: malformed disclosures fail closed, never throw
  let total = true;
  for (const bad of [null, undefined, {}, { doc: {} }, { doc: view.doc, disclosed: 'x' }, { doc: { ...view.doc, root: 5 }, disclosed: [] }, 42, []]) {
    try { if (verifyRedacted(bad, signer.publicKey).verified !== false) total = false; } catch { total = false; }
  }
  ok(total, 'TOTAL: malformed disclosures -> verified:false, never throws');

  // 8. cross-doc splice: a path/leaf from a DIFFERENT signed doc must not validate against this doc's root
  const other = buildRedactable(FIELDS, signer.secretKey, signer.publicKey, { ctx: 'other-doc' });
  const spliced = { doc: view.doc, disclosed: redact(other, ['org']).disclosed };
  ok(verifyRedacted(spliced, signer.publicKey).verified === false, 'leaf+path from a different doc spliced under this root -> FAILS');

  console.log('pqredact self-test: ' + pass + ' pass, ' + fail2 + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail2 ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqredact\.mjs$/.test(process.argv[1] || '')) selfTest();
