/*!
 * pqinduct — The Order of the Lemniscate: cryptographic-merit INDUCTION (Cycle I). Reference, DRAFT, standalone.
 *
 * A Cicada-3301-style induction, post-quantum: you earn standing by SOLVING, not buying. The whole arc is
 * runnable + self-testing on our own SDK (pqsign transparency log + pqcouncil-style attestation):
 *   Layer 1 (outer ring)  — steganography (LSB) + a classical stream cipher: extract a key, decrypt the
 *                           manifest payload, recover the cycle NONCE + inner-ring instructions.
 *   Layer 2 (inner ring)  — the solver generates their OWN ML-DSA-87 keypair and signs a canonical challenge
 *                           bound to (cycle, nonce, their identifier, their pk) — proving real PQC competence.
 *   Layer 3 (inclusion)   — the verified submission is appended to the pqsign transparency log; STH +
 *                           Merkle inclusion proof give a third-party-anchorable record.
 *   Layer 4 (credential)  — the Order issues a soulbound, NON-economic, NON-transferable recognition
 *                           credential (ML-DSA-87 signed, optionally witness co-signed), binding the chain.
 * The manifest itself is DUAL-SIGNED for algorithm diversity: ML-DSA-87 (lattice) + SLH-DSA-256s (hash-based),
 * fail-closed (BOTH must verify).
 *
 * HONEST LIMITS (the bright line + the Team-Apex review):
 *  - RECOGNITION, not a security: non-economic, non-transferable, NO profit/governance/dividend/claim and NO
 *    priority or service/economic access (the substantive FINMA/MiCA firewall, committed in the credential).
 *    Keep it on the Foundation's CULTURAL layer with an absolute economic firewall; counsel + a FINMA no-action
 *    view before any launch (Mistral).
 *  - Merit binds to POSSESSION OF THE SOLUTION SECRET + the solver's OWN key (not just the shareable nonce), so a
 *    shared nonce alone cannot earn a credential. A public puzzle is still ultimately shareable (you can hand over
 *    the cipher key); full anti-share + Sybil-resistance = a per-solver assignment nonce + ZK-personhood nullifier
 *    (gated-registration layer, deferred). Cycle I proves OPERATIONAL PQC competence + puzzle-solving, NOT
 *    cryptographic-research skill (Grok) — later cycles raise difficulty (cryptanalysis / build-a-verifier).
 *  - Anti-equivocation: anchor manifestId() in a public bulletin / the log BEFORE release; verifiers pin it.
 *  - Third-party assurance: the credential CARRIES a Merkle inclusion proof; the STH root must come from a
 *    WITNESSED/threshold-signed, gossiped log (not a single operator). On-chain (ERC-5192) mint is out of scope.
 *  - GDPR: the log stores ONLY hashes (pubkey-hash, sig-hash) + a pseudonymous handle — no PII; never link an
 *    off-chain identity to a leaf.
 * New, self-contained reference code; touches no production key. Self-test: node pqinduct.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_shake_256s as slh256s } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { PQTransparencyLog, verifySTH, leafHash, entryLeafHash, verifyInclusionRFC } from './pqsign.mjs';

const MANIFEST_CTX = utf8ToBytes('trelyan-lemniscate-manifest-v1');
const INNER_CTX = utf8ToBytes('trelyan-lemniscate-inner-ring-v1');
const CRED_CTX = utf8ToBytes('trelyan-lemniscate-credential-v1');

const sha = (s) => bytesToHex(sha256(typeof s === 'string' ? utf8ToBytes(s) : s));
// Reference canonical JSON (sorted keys). PRODUCTION PROFILE = RFC 8785 (JCS) or deterministic CBOR
// (RFC 8949); signer + verifier MUST share one profile. Fail-closed on the ambiguities a cross-impl
// attacker would exploit (council/DeepSeek): non-finite numbers + undefined are rejected, not silently coerced.
function canonicalize(v) {
  if (v === undefined) throw new Error('canonicalize: undefined is not serializable (fail-closed)');
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('canonicalize: non-finite number (fail-closed)');
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}

/* ---------- Layer 1 primitives: LSB stego + classical stream cipher ---------- */
// keystream block i = sha256(key || LE32(i)); XOR over data (symmetric). Reference cipher, not for secrecy of value.
function streamXor(key, data) {
  const out = new Uint8Array(data.length);
  for (let off = 0, i = 0; off < data.length; off += 32, i++) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, i, true);
    const ks = sha256(concatBytes(key, ctr));
    for (let j = 0; j < 32 && off + j < data.length; j++) out[off + j] = data[off + j] ^ ks[j];
  }
  return out;
}
// embed secretBytes into the LSBs of cover (1 bit/byte); cover.length must be >= 8*secretBytes.length
function lsbEmbed(cover, secret) {
  const out = cover.slice();
  for (let i = 0; i < secret.length; i++) for (let b = 0; b < 8; b++) {
    const bit = (secret[i] >> (7 - b)) & 1, idx = i * 8 + b;
    out[idx] = (out[idx] & 0xfe) | bit;
  }
  return out;
}
function lsbExtract(stego, nBytes) {
  const out = new Uint8Array(nBytes);
  for (let i = 0; i < nBytes; i++) { let v = 0; for (let b = 0; b < 8; b++) v = (v << 1) | (stego[i * 8 + b] & 1); out[i] = v; }
  return out;
}

/* ---------- Layer 0/1: create a cycle (manifest + outer-ring puzzle) ---------- */
// order keys: { mldsa:{secretKey,publicKey}, slh:{secretKey,publicKey} }; logPub binds the expected log key.
export function createCycle({ cycleId, order, logPub, instructions, opts = {} }) {
  const nonce = opts.nonce || bytesToHex(randomBytes(16));
  const cipherKey = opts.cipherKey ? hexToBytes(opts.cipherKey) : randomBytes(16);
  // the hidden inner-ring payload the solver must recover
  const payload = utf8ToBytes(canonicalize({ stage: 'inner-ring', cycle: cycleId, nonce, instructions: instructions || 'Generate an ML-DSA-87 keypair and sign the challenge.' }));
  const ciphertext = streamXor(cipherKey, payload);
  // hide the cipher key in the LSBs of a cover ("image") artifact
  const cover = opts.cover ? hexToBytes(opts.cover) : randomBytes(8 * cipherKey.length + 64);
  const coverStego = lsbEmbed(cover, cipherKey);
  const rules = opts.rules || 'Recognition credential. Non-economic, non-transferable, not a security. Rules+keys+code public; the only secret is the solution.';

  const body = {
    cover_hex: bytesToHex(coverStego),
    cipher_hex: bytesToHex(ciphertext),
    order_mldsa_pub_hex: bytesToHex(order.mldsa.publicKey),
    order_slh_pub_hex: bytesToHex(order.slh.publicKey),
    log_pub_hex: bytesToHex(logPub),
    public_instructions: 'Extract the 16-byte key from the LSBs of cover_hex, then stream-decrypt cipher_hex to recover the cycle nonce + inner-ring instructions.',
    rules,
  };
  // signed core commits the ARTIFACT HASHES + pinned key hashes (compact; verifier rechecks artifacts hash to these)
  const coreObj = {
    v: '0.1', cycle: cycleId,
    cover_sha256: sha(hexToBytes(body.cover_hex)),
    cipher_sha256: sha(hexToBytes(body.cipher_hex)),
    order_mldsa_pub_sha256: sha(order.mldsa.publicKey),
    order_slh_pub_sha256: sha(order.slh.publicKey),
    log_pub_sha256: sha(logPub),
    rules_sha256: sha(rules),
    ts: opts.ts ?? Date.now(),
  };
  const core = utf8ToBytes(canonicalize(coreObj));
  const manifest = {
    ...coreObj, ...body,
    sig_mldsa_hex: bytesToHex(ml_dsa87.sign(core, order.mldsa.secretKey, { context: MANIFEST_CTX })),
    sig_slh_hex: bytesToHex(slh256s.sign(core, order.slh.secretKey)),
  };
  // the secret cycle state the Order retains (to verify submissions); NOT published
  return { manifest, manifestId: sha(core), secret: { nonce, cipherKeyHex: bytesToHex(cipherKey) } };
}

const manifestCore = (m) => utf8ToBytes(canonicalize({
  v: m.v, cycle: m.cycle, cover_sha256: m.cover_sha256, cipher_sha256: m.cipher_sha256,
  order_mldsa_pub_sha256: m.order_mldsa_pub_sha256, order_slh_pub_sha256: m.order_slh_pub_sha256,
  log_pub_sha256: m.log_pub_sha256, rules_sha256: m.rules_sha256, ts: m.ts,
}));

// the manifest's identity = hash of its signed core. ANCHOR this in the transparency log / a public bulletin
// BEFORE release so the Order cannot equivocate (serve different manifests to different solvers); verifiers
// then pin opts.expectedManifestId from that public commitment.
export function manifestId(m) { return sha(manifestCore(m)); }

// verify with PINNED trusted order keys (out-of-band) — fail-closed: BOTH signatures + artifact binding must hold.
export function verifyManifest(m, trustedOrderMldsaPub, trustedOrderSlhPub, opts = {}) {
  const keysPinned = m.order_mldsa_pub_sha256 === sha(trustedOrderMldsaPub) && m.order_slh_pub_sha256 === sha(trustedOrderSlhPub);
  const artifactsBound = m.cover_sha256 === sha(hexToBytes(m.cover_hex)) && m.cipher_sha256 === sha(hexToBytes(m.cipher_hex));
  const core = manifestCore(m);
  let mldsaOk = false, slhOk = false;
  try { mldsaOk = ml_dsa87.verify(hexToBytes(m.sig_mldsa_hex), core, trustedOrderMldsaPub, { context: MANIFEST_CTX }); } catch { mldsaOk = false; }
  try { slhOk = slh256s.verify(hexToBytes(m.sig_slh_hex), core, trustedOrderSlhPub); } catch { slhOk = false; }
  const idOk = !opts.expectedManifestId || sha(core) === opts.expectedManifestId; // anti-equivocation pin
  const verified = keysPinned && artifactsBound && mldsaOk && slhOk && idOk;
  return { verified, keysPinned, artifactsBound, mldsaOk, slhOk, idOk, reason: verified ? 'manifest verified (dual-signed, artifacts bound, keys pinned)' : !keysPinned ? 'order keys not pinned' : !artifactsBound ? 'puzzle artifacts do not match signed hashes' : !idOk ? 'manifest id != the publicly-committed cycle manifest (possible equivocation)' : !mldsaOk ? 'ML-DSA signature invalid' : 'SLH-DSA diversity signature invalid (fail-closed)' };
}

/* ---------- Layer 1 reference solver (proves the puzzle is solvable) ---------- */
export function solveOuterRing(m) {
  const cover = hexToBytes(m.cover_hex);
  const key = lsbExtract(cover, 16);
  const payload = streamXor(key, hexToBytes(m.cipher_hex));
  // also returns the recovered SOLUTION SECRET (the cipher key) — the inner ring binds possession of it
  // to the solver's own key, so a shared public nonce alone cannot earn a credential.
  try { const inner = JSON.parse(new TextDecoder().decode(payload)); return { ...inner, cipher_key_hex: bytesToHex(key) }; } catch { return null; }
}

/* ---------- Layer 2: inner ring — the solver proves PQC competence ---------- */
// solver generates their OWN ML-DSA-87 key; signs a challenge binding (cycle, recovered nonce, their id, pk)
// AND a solution_binding = H(cipher_key || their pk) proving POSSESSION OF THE SOLUTION SECRET bound to THIS key.
// `recovered` = the object returned by solveOuterRing (must include nonce + cipher_key_hex).
export function solverProve({ cycleId, recovered, solverId, solverKey, opts = {} }) {
  const solution_binding = sha(concatBytes(hexToBytes(recovered.cipher_key_hex), solverKey.publicKey));
  const challenge = { v: '0.1', cycle: cycleId, nonce: recovered.nonce, solution_binding, solver: solverId, pk_sha256: sha(solverKey.publicKey), ts: opts.ts ?? Date.now() };
  const sig = ml_dsa87.sign(utf8ToBytes(canonicalize(challenge)), solverKey.secretKey, { context: INNER_CTX });
  return { challenge, pk_hex: bytesToHex(solverKey.publicKey), sig_hex: bytesToHex(sig) };
}
// the Order verifies a submission against the cycle's TRUE nonce + TRUE cipher key (known only to the Order until solved)
export function verifySubmission({ submission, cycleId, trueNonce, trueCipherKeyHex }) {
  const c = submission.challenge;
  const cycleOk = c.cycle === cycleId;
  const nonceOk = c.nonce === trueNonce;            // proves the puzzle was solved (public once shared)
  const pkBound = c.pk_sha256 === sha(hexToBytes(submission.pk_hex)); // challenge commits the solver's own key
  // possession of the solution SECRET, bound to this key: a shared nonce alone does NOT let a different key qualify
  const expectedBinding = sha(concatBytes(hexToBytes(trueCipherKeyHex), hexToBytes(submission.pk_hex)));
  const solutionOk = c.solution_binding === expectedBinding;
  let sigOk = false;
  try { sigOk = ml_dsa87.verify(hexToBytes(submission.sig_hex), utf8ToBytes(canonicalize(c)), hexToBytes(submission.pk_hex), { context: INNER_CTX }); } catch { sigOk = false; }
  const valid = cycleOk && nonceOk && pkBound && solutionOk && sigOk;
  return { valid, cycleOk, nonceOk, pkBound, solutionOk, sigOk, reason: valid ? 'submission valid (solution possessed + bound to solver key + PQ competence)' : !cycleOk ? 'wrong cycle' : !nonceOk ? 'nonce not recovered — puzzle not solved' : !solutionOk ? 'solution secret not possessed / not bound to this key (a shared nonce alone is insufficient)' : !pkBound ? 'challenge does not bind the submitted key' : 'inner-ring signature invalid' };
}

/* ---------- Layer 3: transparency-log inclusion (uses the pqsign log) ---------- */
export function logSubmission(log, submission) {
  const entry = { kind: 'lemniscate-induction-submission', cycle: submission.challenge.cycle, solver: submission.challenge.solver, pk_sha256: submission.challenge.pk_sha256, sig_sha256: sha(hexToBytes(submission.sig_hex)) };
  const index = log.append(entry);
  return { index, entry };
}
export function verifyLogInclusion({ entry, inclusion, sth }, logPub) {
  const sthOk = verifySTH(sth, logPub);
  const expectedLeaf = entryLeafHash(entry);
  const leafBound = bytesToHex(expectedLeaf) === bytesToHex(inclusion.leaf);
  // HARDENING (RFC-6962 §2.1.1): bind to (index, tree_size) + require tree_size to match the signed STH.
  const treeSizeOk = inclusion.tree_size === sth.tree_size;
  const incOk = leafBound && treeSizeOk && verifyInclusionRFC(expectedLeaf, inclusion.index, sth.tree_size, (inclusion.proof || []).map((p) => p.sibling), hexToBytes(sth.root_hex));
  return { verified: sthOk && incOk, sthOk, incOk, leafBound, treeSizeOk };
}

/* ---------- Layer 4: the soulbound recognition credential ---------- */
const CRED_TERMS = 'Recognition only. Non-economic, non-transferable, not a security. Confers NO profit, dividend, governance, claim on assets, priority, or service/economic access. Rules+keys+code public.';
function serializeInclusion(inc) {
  return { index: inc.index, tree_size: inc.tree_size, leaf_hex: bytesToHex(inc.leaf), proof: (inc.proof || []).map((p) => ({ sibling_hex: bytesToHex(p.sibling), right: p.right })) };
}
// opts.seenSubjects (a Set) enforces one-credential-per-identity at issuance (throws on a repeat subject key).
export function issueCredential({ cycleId, submission, logIndex, sth, inclusion, entry }, order, opts = {}) {
  const subject = submission.challenge.pk_sha256;
  if (opts.seenSubjects && opts.seenSubjects.has(subject)) throw new Error('one-credential-per-identity: subject already inducted');
  const credCore = {
    v: '0.1', kind: 'recognition', soulbound: true, transferable: false, not_a_security: true,
    no_economic_or_service_access: true, confers: 'recognition-only', terms: CRED_TERMS,
    order: opts.order || 'Order of the Lemniscate', cycle: cycleId, tier: opts.tier || 'Post-Quantum Attested',
    subject_pk_sha256: subject, solver: submission.challenge.solver,
    log_index: logIndex, sth_root: sth.root_hex, sth_tree_size: sth.tree_size, sth_ts: sth.ts, ts: opts.ts ?? Date.now(),
  };
  const core = utf8ToBytes(canonicalize(credCore));
  const cred = {
    ...credCore,
    evidence: (inclusion && entry) ? { inclusion: serializeInclusion(inclusion), entry } : null, // self-contained, verifiable against sth_root
    signatures: [{ signer_pub_hex: bytesToHex(order.mldsa.publicKey), sig_hex: bytesToHex(ml_dsa87.sign(core, order.mldsa.secretKey, { context: CRED_CTX })), role: 'order' }],
  };
  if (opts.seenSubjects) opts.seenSubjects.add(subject);
  return cred;
}
export function addCredentialWitness(cred, witnessSecret, witnessPub, role = 'witness') {
  const core = utf8ToBytes(canonicalize(credCoreOf(cred)));
  cred.signatures.push({ signer_pub_hex: bytesToHex(witnessPub), sig_hex: bytesToHex(ml_dsa87.sign(core, witnessSecret, { context: CRED_CTX })), role });
  return cred;
}
const credCoreOf = (c) => ({ v: c.v, kind: c.kind, soulbound: c.soulbound, transferable: c.transferable, not_a_security: c.not_a_security, no_economic_or_service_access: c.no_economic_or_service_access, confers: c.confers, terms: c.terms, order: c.order, cycle: c.cycle, tier: c.tier, subject_pk_sha256: c.subject_pk_sha256, solver: c.solver, log_index: c.log_index, sth_root: c.sth_root, sth_tree_size: c.sth_tree_size, sth_ts: c.sth_ts, ts: c.ts });

// verify with the PINNED order key; verifies the carried Merkle inclusion against the credential's sth_root;
// optionally require >=minWitnesses trusted witnesses + bind to a known/witnessed STH root (opts.expectedSthRoot).
export function verifyCredential(cred, trustedOrderPub, opts = {}) {
  const core = utf8ToBytes(canonicalize(credCoreOf(cred)));
  const trustedW = (opts.trustedWitnesses || []).map((h) => h.toLowerCase());
  let orderOk = false; const witnessSet = new Set();
  for (const s of cred.signatures || []) {
    let ok = false; try { ok = ml_dsa87.verify(hexToBytes(s.sig_hex), core, hexToBytes(s.signer_pub_hex), { context: CRED_CTX }); } catch { ok = false; }
    if (!ok) continue;
    if (s.signer_pub_hex.toLowerCase() === bytesToHex(trustedOrderPub).toLowerCase()) orderOk = true;
    if (trustedW.includes(s.signer_pub_hex.toLowerCase())) witnessSet.add(s.signer_pub_hex.toLowerCase());
  }
  const soulboundOk = cred.soulbound === true && cred.transferable === false;
  const econOk = cred.not_a_security === true && cred.no_economic_or_service_access === true; // the substantive firewall (FINMA/MiCA)
  const rootOk = !opts.expectedSthRoot || cred.sth_root === opts.expectedSthRoot;
  // verify the carried inclusion proof against the credential's (signed) sth_root — proves the leaf is really in the log
  let inclusionOk = true, inclusionPresent = false;
  if (cred.evidence && cred.evidence.inclusion && cred.evidence.entry) {
    inclusionPresent = true;
    const expectedLeaf = entryLeafHash(cred.evidence.entry);
    const inc = cred.evidence.inclusion;
    const leafBound = bytesToHex(expectedLeaf) === inc.leaf_hex;
    // HARDENING (RFC-6962): bind to (index, tree_size) against the credential's SIGNED sth_root + sth_tree_size.
    const treeSizeOk = inc.tree_size === cred.sth_tree_size;
    const auditPath = (inc.proof || []).map((p) => hexToBytes(p.sibling_hex));
    inclusionOk = leafBound && treeSizeOk && verifyInclusionRFC(expectedLeaf, inc.index, cred.sth_tree_size, auditPath, hexToBytes(cred.sth_root));
  } else if (opts.requireInclusion) inclusionOk = false;
  const minW = opts.minWitnesses || 0;
  const witnessed = witnessSet.size >= minW && minW > 0;
  const verified = orderOk && soulboundOk && econOk && rootOk && inclusionOk && witnessSet.size >= minW;
  return { verified, orderOk, soulboundOk, econOk, rootOk, inclusionOk, inclusionPresent, witness_count: witnessSet.size, witnessed, assurance: witnessed ? 'witnessed-record' : 'order-signed',
    reason: verified ? 'credential verified (order-signed, soulbound, economic-firewall, log-inclusion proven)' : !orderOk ? 'no valid signature from the pinned Order key' : !soulboundOk ? 'credential is not soulbound/non-transferable' : !econOk ? 'credential missing the non-security/no-economic-access firewall' : !rootOk ? 'credential not bound to the expected log root' : !inclusionOk ? 'Merkle inclusion proof does not verify against the credential STH root' : 'insufficient witness co-signatures' };
}

/* ---------- self-test: node pqinduct.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // Order keys (dual scheme) + log key + a witness
  const order = { mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(11)), slh: slh256s.keygen() };
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(12));
  const witness = ml_dsa87.keygen(new Uint8Array(32).fill(13));

  // 1. create cycle + verify manifest (dual-signed, pinned)
  const { manifest, manifestId: mid, secret } = createCycle({ cycleId: 'LEMNISCATE-CYCLE-I', order, logPub: logKey.publicKey, opts: { ts: 1000 } });
  ok(verifyManifest(manifest, order.mldsa.publicKey, order.slh.publicKey).verified === true, 'manifest dual-signature verifies (ML-DSA + SLH-DSA), artifacts bound');

  // 1b. anti-equivocation: pin the publicly-committed manifest id
  ok(verifyManifest(manifest, order.mldsa.publicKey, order.slh.publicKey, { expectedManifestId: mid }).verified === true
    && verifyManifest(manifest, order.mldsa.publicKey, order.slh.publicKey, { expectedManifestId: 'ff'.repeat(32) }).idOk === false, 'manifest id pin: correct id passes, wrong id -> idOk false (equivocation caught)');

  // 2. solve the outer ring -> recover the true nonce + the solution secret (cipher key)
  const recovered = solveOuterRing(manifest);
  ok(recovered && recovered.nonce === secret.nonce && recovered.cipher_key_hex === secret.cipherKeyHex, 'outer ring solved -> recovered nonce + solution secret');

  // 3. inner ring: solver proves PQC competence + possession of the solution, bound to their OWN key
  const solverKey = ml_dsa87.keygen(new Uint8Array(32).fill(21));
  const submission = solverProve({ cycleId: manifest.cycle, recovered, solverId: 'solver:alpha', solverKey, opts: { ts: 1001 } });
  ok(verifySubmission({ submission, cycleId: manifest.cycle, trueNonce: secret.nonce, trueCipherKeyHex: secret.cipherKeyHex }).valid === true, 'inner-ring submission valid (solution possessed + bound to key + PQ competence)');

  // 4. log inclusion
  const log = new PQTransparencyLog();
  [0, 1].forEach((i) => log.append({ kind: 'other', i })); // pad so the Merkle tree is non-trivial
  const { index, entry } = logSubmission(log, submission);
  log.append({ kind: 'other', i: 9 });
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 2000 });
  const inc = log.inclusion(index);
  ok(verifyLogInclusion({ entry, inclusion: inc, sth }, logKey.publicKey).verified === true, 'submission is included in the transparency log (STH + Merkle proof)');

  // 5. credential issued (carries inclusion proof) + verified; firewall flags present
  const cred = issueCredential({ cycleId: manifest.cycle, submission, logIndex: index, sth, inclusion: inc, entry }, order, { ts: 2001, seenSubjects: new Set() });
  const cv = verifyCredential(cred, order.mldsa.publicKey, { expectedSthRoot: sth.root_hex });
  ok(cv.verified === true && cv.inclusionOk === true && cred.soulbound === true && cred.transferable === false && cred.not_a_security === true && cred.no_economic_or_service_access === true && cred.kind === 'recognition', 'credential verifies; soulbound, not-a-security, no economic access, inclusion proven');

  // 5b. witnessed credential
  addCredentialWitness(cred, witness.secretKey, witness.publicKey);
  ok(verifyCredential(cred, order.mldsa.publicKey, { trustedWitnesses: [bytesToHex(witness.publicKey)], minWitnesses: 1 }).assurance === 'witnessed-record', 'witness co-signs -> credential becomes a witnessed-record');

  // 5c. RFC index/tree_size BINDING on the (UNSIGNED) carried proof — tampering it must be caught by the binding
  const credIdxT = JSON.parse(JSON.stringify(cred)); credIdxT.evidence.inclusion.index = credIdxT.evidence.inclusion.index + 1;
  ok(verifyCredential(credIdxT, order.mldsa.publicKey, { expectedSthRoot: sth.root_hex }).inclusionOk === false, 'tampered inclusion index in the credential -> inclusionOk FALSE (RFC position binding)');
  const credTsT = JSON.parse(JSON.stringify(cred)); credTsT.evidence.inclusion.tree_size = credTsT.evidence.inclusion.tree_size + 1;
  ok(verifyCredential(credTsT, order.mldsa.publicKey, { expectedSthRoot: sth.root_hex }).inclusionOk === false, 'inclusion tree_size != signed sth_tree_size -> inclusionOk FALSE');

  // ---- negatives ----
  // 6. tampered manifest (flip a ciphertext byte) -> dual-sig fails closed
  const tampered = { ...manifest, cipher_hex: (manifest.cipher_hex.slice(0, -2) + (manifest.cipher_hex.slice(-2) === '00' ? '01' : '00')) };
  ok(verifyManifest(tampered, order.mldsa.publicKey, order.slh.publicKey).verified === false, 'tampered manifest artifact -> verify FAILS (artifact binding / signature)');

  // 7. SLH-DSA diversity leg forged but ML-DSA intact -> still FAILS (fail-closed requires both)
  const slhForged = { ...manifest, sig_slh_hex: bytesToHex(slh256s.sign(manifestCore(manifest), slh256s.keygen().secretKey)) };
  const slhRes = verifyManifest(slhForged, order.mldsa.publicKey, order.slh.publicKey);
  ok(slhRes.verified === false && slhRes.mldsaOk === true && slhRes.slhOk === false, 'forged SLH-DSA leg alone -> FAILS (diversity is fail-closed)');

  // 8. wrong nonce in the inner ring (didn't actually solve) -> submission invalid
  const badSub = solverProve({ cycleId: manifest.cycle, recovered: { nonce: 'deadbeef'.repeat(4), cipher_key_hex: secret.cipherKeyHex }, solverId: 'solver:beta', solverKey, opts: { ts: 1002 } });
  ok(verifySubmission({ submission: badSub, cycleId: manifest.cycle, trueNonce: secret.nonce, trueCipherKeyHex: secret.cipherKeyHex }).nonceOk === false, 'inner ring with wrong nonce -> INVALID (puzzle not solved)');

  // 8b. SHARE-RESISTANCE: a different key with ONLY the public nonce (not the solution secret) cannot qualify
  const leechKey = ml_dsa87.keygen(new Uint8Array(32).fill(22));
  const leechSub = solverProve({ cycleId: manifest.cycle, recovered: { nonce: secret.nonce, cipher_key_hex: '00'.repeat(16) }, solverId: 'solver:leech', solverKey: leechKey, opts: { ts: 1003 } });
  ok(verifySubmission({ submission: leechSub, cycleId: manifest.cycle, trueNonce: secret.nonce, trueCipherKeyHex: secret.cipherKeyHex }).solutionOk === false, 'shared nonce only (no solution secret) -> INVALID (merit is non-transferable)');

  // 9. forged submission: claim a pk you do not control
  const otherKey = ml_dsa87.keygen(new Uint8Array(32).fill(31));
  const forgedSub = { ...submission, pk_hex: bytesToHex(otherKey.publicKey) };
  ok(verifySubmission({ submission: forgedSub, cycleId: manifest.cycle, trueNonce: secret.nonce, trueCipherKeyHex: secret.cipherKeyHex }).valid === false, 'submission claiming an unowned key -> INVALID');

  // 10. credential bound to a DIFFERENT log root -> verify fails under the expected root
  ok(verifyCredential(cred, order.mldsa.publicKey, { expectedSthRoot: 'ff'.repeat(32) }).verified === false, 'credential checked against a wrong STH root -> FAILS');

  // 11. credential signed by a non-order key -> not verified
  ok(verifyCredential(cred, otherKey.publicKey, {}).orderOk === false, 'credential under a non-Order key -> orderOk false');

  // 12. tampered inclusion evidence (swap the logged entry) -> inclusion no longer verifies
  const credT = JSON.parse(JSON.stringify(cred)); credT.evidence.entry.solver = 'someone-else';
  ok(verifyCredential(credT, order.mldsa.publicKey).inclusionOk === false, 'tampered credential inclusion evidence -> inclusionOk false');

  // 13. one-credential-per-identity: re-issuing for the same subject throws
  const seen = new Set();
  issueCredential({ cycleId: manifest.cycle, submission, logIndex: index, sth, inclusion: inc, entry }, order, { seenSubjects: seen });
  let dup = false; try { issueCredential({ cycleId: manifest.cycle, submission, logIndex: index, sth, inclusion: inc, entry }, order, { seenSubjects: seen }); } catch { dup = true; }
  ok(dup, 'second credential for the same subject key -> rejected (one-per-identity)');

  console.log('pqinduct self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqinduct\.mjs$/.test(process.argv[1] || '')) selfTest();
