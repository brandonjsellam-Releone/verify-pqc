/*!
 * pqvc — QuantumDNA: post-quantum verifiable credentials + `did:trelyan` + selective disclosure (reference, DRAFT).
 *
 * A W3C-VC-shaped credential whose proof is HYBRID — Ed25519 (classical) ∧ ML-DSA-87 (lattice) ∧ optional SLH-DSA-256f
 * (hash-based) — over a canonical credential core. The credential's CLAIMS are carried as a salted Merkle doc (via
 * pqredact), so a holder can present only SOME claims while proving the rest were in the issuer-signed credential and
 * leaking nothing about the hidden ones. Issuer + subject + holder are `did:trelyan` identifiers derived from their
 * hybrid public keys. Revocation is a published id-set; holder binding is an optional proof-of-possession.
 *
 * FALSIFIABLE PROPERTIES a third party can check: (1) the credential was issued by the PINNED issuer (issuer DID binds
 * its keys; hybrid proof verifies — forging needs classical AND lattice [AND hash-based] breaks); (2) it is unexpired
 * and not on the revocation set; (3) each DISCLOSED claim is provably a member of the signed claims root, while hidden
 * claims are unrecoverable (salted commitments); (4) with proof-of-possession, the presenter controls the subject DID.
 * HONEST: `did:trelyan` is NOT (yet) a W3C-recognized DID method; this is a self-anchored reference scheme. Unaudited.
 *
 * Dependency-light: @noble/curves (ed25519) + @noble/post-quantum (ml-dsa-87, slh-dsa) + @noble/hashes (sha256) + ./pqredact.
 * Self-test: node pqvc.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { buildRedactable, redact, verifyRedacted } from './pqredact.mjs';

const VC_CTX = utf8ToBytes('trelyan-quantumdna-vc-v1');       // credential proof domain (Ed25519 + ML-DSA)
const VC_SLH_CTX = utf8ToBytes('trelyan-quantumdna-vc-slh-v1'); // optional hash-based leg
const VP_CTX = utf8ToBytes('trelyan-quantumdna-vp-v1');        // holder proof-of-possession domain

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

// did:trelyan derived from the holder/issuer hybrid public keys (binds the DID to its verification keys).
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);  // accept a {publicKey} keypair OR a raw Uint8Array pubkey
export function makeDid(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('keys must be { ed, mldsa[, slh] }');
  // FULL 256-bit id binding the COMPLETE hybrid key set (ed + mldsa + slh-if-present), versioned preimage. Apex-team
  // hardening: a 40-hex (160-bit) id had only ~2^80 collision resistance; full SHA-256 removes that and binds every leg.
  const id = bytesToHex(sha256(concatBytes(utf8ToBytes('did:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
  return 'did:trelyan:' + id;
}
export function didDocument(keys) {
  const did = makeDid(keys);
  const verificationMethod = [
    { id: did + '#ed', type: 'Ed25519', publicKeyHex: bytesToHex(_pub(keys.ed)) },
    { id: did + '#mldsa', type: 'ML-DSA-87', publicKeyHex: bytesToHex(_pub(keys.mldsa)) },
  ];
  if (keys.slh) verificationMethod.push({ id: did + '#slh', type: 'SLH-DSA-SHA2-256f', publicKeyHex: bytesToHex(_pub(keys.slh)) });
  return { '@context': 'https://www.w3.org/ns/did/v1', id: did, verificationMethod };
}

function hybridSign(coreBytes, keys) {
  const proof = {
    ed_sig: bytesToHex(ed25519.sign(concatBytes(VC_CTX, coreBytes), keys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, keys.mldsa.secretKey, { context: VC_CTX })),
  };
  if (keys.slh) proof.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, keys.slh.secretKey, { context: VC_SLH_CTX }));
  return proof;
}
function hybridVerify(coreBytes, proof, trusted) {
  let edOk = false, pqOk = false, slhOk = true;
  try { edOk = ed25519.verify(hexToBytes(proof.ed_sig), concatBytes(VC_CTX, coreBytes), trusted.ed); } catch { edOk = false; }
  try { pqOk = ml_dsa87.verify(hexToBytes(proof.mldsa_sig), coreBytes, trusted.mldsa, { context: VC_CTX }); } catch { pqOk = false; }
  if (trusted.slh) { try { slhOk = !!(proof.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(proof.slh_sig), coreBytes, trusted.slh, { context: VC_SLH_CTX })); } catch { slhOk = false; } }
  return edOk && pqOk && slhOk;
}

// issue a credential. claims = flat {key:value}. issuerKeys = { ed, mldsa[, slh] }. Returns { vc, holder } — `vc` is
// publishable; `holder` (fields+salts) is kept privately so the holder can later selectively disclose.
export function issueCredential({ issuerKeys, subjectDid, claims, id, issuanceDate, expirationDate, type }) {
  if (!issuerKeys || !subjectDid || !claims || !id) throw new Error('issueCredential needs { issuerKeys, subjectDid, claims, id }');
  const fields = Object.keys(claims).sort().map((k) => ({ key: k, value: claims[k] }));
  const r = buildRedactable(fields, issuerKeys.mldsa.secretKey, issuerKeys.mldsa.publicKey, { ctx: 'vc:' + id });  // salted Merkle of claims
  const core = {
    v: '1', id, type: type || ['VerifiableCredential'], issuer: makeDid(issuerKeys), subject: String(subjectDid),
    issuanceDate: issuanceDate ?? null, expirationDate: expirationDate ?? null, claims_root: r.doc.root,
  };
  const coreBytes = utf8ToBytes(canon(core));
  const vc = { ...core, claims_doc: r.doc, proof: { type: 'TrelyanHybrid2026', ...hybridSign(coreBytes, issuerKeys) } };
  return { vc, holder: { doc: r.doc, fields: r.fields, salts: r.salts } };
}
function vcCore(vc) {
  return { v: vc.v, id: vc.id, type: vc.type, issuer: vc.issuer, subject: vc.subject, issuanceDate: vc.issuanceDate ?? null, expirationDate: vc.expirationDate ?? null, claims_root: vc.claims_root };
}

// TOTAL / fail-closed. trustedIssuer = { ed, mldsa[, slh] } pinned issuer pubkeys. opts.now (ms) + expirationDate for
// expiry; opts.revoked = Set/array of revoked ids; opts.requireHybrid3 not needed (slh required iff trustedIssuer.slh).
export function verifyCredential(vc, trustedIssuer, opts = {}) {
  try {
    if (!vc || typeof vc !== 'object' || !vc.proof || !trustedIssuer || !trustedIssuer.ed || !trustedIssuer.mldsa) return { verified: false };
    if (vc.issuer !== makeDid(trustedIssuer)) return { verified: false, reason: 'issuer DID != pinned issuer keys' };
    const sigOk = hybridVerify(utf8ToBytes(canon(vcCore(vc))), vc.proof, trustedIssuer);
    if (!sigOk) return { verified: false, reason: 'hybrid proof invalid' };
    const expired = vc.expirationDate != null && opts.now != null && Number(opts.now) > Number(vc.expirationDate);
    const revokedSet = opts.revoked instanceof Set ? opts.revoked : new Set(opts.revoked || []);
    const revoked = revokedSet.has(vc.id);
    return { verified: !expired && !revoked, sigOk, expired, revoked, issuer: vc.issuer, subject: vc.subject, id: vc.id };
  } catch { return { verified: false }; }
}

// holder builds a Verifiable Presentation disclosing only `discloseClaims`. holderRecord = the { doc, fields, salts }
// returned at issuance. Optional holderKeys + nonce add proof-of-possession (proves control of the subject DID).
export function present(vc, holderRecord, discloseClaims, opts = {}) {
  const disclosure = redact({ doc: vc.claims_doc, fields: holderRecord.fields, salts: holderRecord.salts }, discloseClaims || []);
  const vp = { vc, disclosure };
  if (opts.holderKeys && opts.nonce) {
    const b = concatBytes(VP_CTX, utf8ToBytes(String(opts.nonce) + '|' + vc.id));
    vp.holder = { did: makeDid(opts.holderKeys),
      ed_sig: bytesToHex(ed25519.sign(b, opts.holderKeys.ed.secretKey)),
      mldsa_sig: bytesToHex(ml_dsa87.sign(concatBytes(VP_CTX, utf8ToBytes(String(opts.nonce) + '|' + vc.id)), opts.holderKeys.mldsa.secretKey, { context: VP_CTX })),
      nonce: String(opts.nonce) };
  }
  return vp;
}

// verify a presentation: VC valid + disclosed claims provably bound to THIS VC's claims root + (optional) holder PoP.
export function verifyPresentation(vp, trustedIssuer, opts = {}) {
  try {
    if (!vp || !vp.vc || !vp.disclosure) return { verified: false };
    const cred = verifyCredential(vp.vc, trustedIssuer, opts);
    if (!cred.verified) return { verified: false, reason: 'credential: ' + (cred.reason || 'invalid'), cred };
    // disclosed claims must verify under the issuer's ML-DSA key AND belong to THIS credential's claims root
    const disc = verifyRedacted(vp.disclosure, trustedIssuer.mldsa);
    const rootBound = vp.disclosure.doc && vp.disclosure.doc.root === vp.vc.claims_root;
    if (!disc.verified || !rootBound) return { verified: false, reason: 'disclosed claims not bound to the signed credential' };
    let holderOk = true;
    if (opts.requireHolderProof) {
      holderOk = false;
      const h = vp.holder;
      if (h && h.did === vp.vc.subject && opts.holderKeys && h.did === makeDid(opts.holderKeys)) {
        const b = concatBytes(VP_CTX, utf8ToBytes(String(h.nonce) + '|' + vp.vc.id));
        let e = false, m = false;
        try { e = ed25519.verify(hexToBytes(h.ed_sig), b, _pub(opts.holderKeys.ed)); } catch { e = false; }
        try { m = ml_dsa87.verify(hexToBytes(h.mldsa_sig), b, _pub(opts.holderKeys.mldsa), { context: VP_CTX }); } catch { m = false; }
        holderOk = e && m && (opts.expectedNonce == null || String(h.nonce) === String(opts.expectedNonce));
      }
    }
    return { verified: holderOk, disclosed: disc.disclosed, subject: vp.vc.subject, issuer: vp.vc.issuer, holderOk };
  } catch { return { verified: false }; }
}

// ---- W3C Verifiable Credentials interop (structural) ----
// Export a QuantumDNA credential in the standard W3C-VC SHAPE so wallets/verifiers can display + extract it. HONEST: the
// proof type is `TrelyanHybrid2026` (Ed25519∧ML-DSA-87[∧SLH]) — structurally interoperable, but NOT a W3C-registered
// Data Integrity cryptosuite; verification uses TRELYAN's hybrid verifier (verifyW3CCredential), not a generic suite.
export function toW3CCredential(vc, claims) {
  const out = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://trelyan.foundation/ns/quantumdna/v1'],
    id: vc.id, type: Array.isArray(vc.type) ? vc.type : ['VerifiableCredential'],
    issuer: vc.issuer, credentialSubject: { id: vc.subject, ...(claims || {}) },
    proof: { type: 'TrelyanHybrid2026', cryptosuite: 'ed25519+ml-dsa-87' + (vc.proof && vc.proof.slh_sig ? '+slh-dsa-256f' : ''), claims_root: vc.claims_root, ...vc.proof },
  };
  if (vc.issuanceDate != null) out.validFrom = vc.issuanceDate;
  if (vc.expirationDate != null) out.validUntil = vc.expirationDate;
  return out;
}
// Verify a W3C-exported credential by reconstructing the TRELYAN core from the standard fields. TOTAL / fail-closed.
export function verifyW3CCredential(w3c, trustedIssuer, opts = {}) {
  try {
    if (!w3c || typeof w3c !== 'object' || !w3c.proof) return { verified: false };
    const core = { v: '1', id: w3c.id, type: w3c.type, issuer: w3c.issuer,
      subject: w3c.credentialSubject && w3c.credentialSubject.id,
      issuanceDate: w3c.validFrom ?? null, expirationDate: w3c.validUntil ?? null, claims_root: w3c.proof.claims_root };
    return verifyCredential({ ...core, proof: w3c.proof }, trustedIssuer, opts);
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqvc.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const issuer = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const holder = { ed: ed(3), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(4)) };
  const tIssuer = { ed: issuer.ed.publicKey, mldsa: issuer.mldsa.publicKey };

  // did:trelyan is deterministic + binds the keys
  ok(makeDid(issuer).startsWith('did:trelyan:') && makeDid(issuer) === makeDid(issuer), 'did:trelyan deterministic');
  ok(makeDid(issuer) !== makeDid(holder), 'distinct keys -> distinct DIDs');
  ok(didDocument(issuer).verificationMethod.length === 2, 'DID document lists the verification keys');
  ok(makeDid(issuer).length === 'did:trelyan:'.length + 64, 'DID id is full 256-bit (apex-team hardening: no 160-bit truncation)');
  ok(makeDid({ ...issuer, slh: slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(9)) }) !== makeDid(issuer), 'DID binds the SLH leg when present (distinct from the 2-leg DID)');

  // issue + verify
  const subjectDid = makeDid(holder);
  const { vc, holder: hrec } = issueCredential({ issuerKeys: issuer, subjectDid, id: 'urn:vc:1',
    claims: { name: 'Ada Lovelace', over18: true, country: 'CH', clearance: 'secret' }, issuanceDate: 1000, expirationDate: 5000, type: ['VerifiableCredential', 'PQClearance'] });
  ok(verifyCredential(vc, tIssuer, { now: 2000 }).verified === true, 'valid credential verifies under the pinned issuer');
  ok(verifyCredential(vc, { ed: holder.ed.publicKey, mldsa: holder.mldsa.publicKey }, { now: 2000 }).verified === false, 'wrong pinned issuer -> FAILS (issuer DID mismatch)');
  ok(verifyCredential(vc, tIssuer, { now: 9000 }).verified === false && verifyCredential(vc, tIssuer, { now: 9000 }).expired === true, 'expired credential -> FAILS');
  ok(verifyCredential(vc, tIssuer, { now: 2000, revoked: ['urn:vc:1'] }).verified === false, 'revoked credential -> FAILS');
  const tamper = JSON.parse(JSON.stringify(vc)); tamper.subject = makeDid(issuer);
  ok(verifyCredential(tamper, tIssuer, { now: 2000 }).verified === false, 'tampered subject -> hybrid proof FAILS');

  // selective disclosure presentation: reveal only {over18, country}, hide name + clearance
  const vp = present(vc, hrec, ['over18', 'country']);
  const pv = verifyPresentation(vp, tIssuer, { now: 2000 });
  ok(pv.verified && pv.disclosed.over18 === true && pv.disclosed.country === 'CH', 'presentation: discloses chosen claims + verifies');
  ok(!('name' in pv.disclosed) && !('clearance' in pv.disclosed), 'undisclosed claims are NOT revealed');
  ok(!JSON.stringify(vp).includes('Ada Lovelace') && !JSON.stringify(vp).includes('secret'), 'hidden claim VALUES never appear in the presentation (salted)');
  // tamper a disclosed claim -> fails
  const vpT = JSON.parse(JSON.stringify(vp)); const f = vpT.disclosure.disclosed.find((x) => x.key === 'over18'); f.value = false;
  ok(verifyPresentation(vpT, tIssuer, { now: 2000 }).verified === false, 'tampered disclosed claim -> presentation FAILS');
  // cross-VC splice: claims disclosure from a different VC must not bind this VC root
  const other = issueCredential({ issuerKeys: issuer, subjectDid, id: 'urn:vc:2', claims: { over18: true, country: 'US' } });
  const vpSplice = { vc, disclosure: present(other.vc, other.holder, ['country']).disclosure };
  ok(verifyPresentation(vpSplice, tIssuer, { now: 2000 }).verified === false, 'cross-VC claims splice -> FAILS (root mismatch)');

  // holder proof-of-possession: presenter proves control of the subject DID
  const vpPoP = present(vc, hrec, ['country'], { holderKeys: holder, nonce: 'chal-xyz' });
  ok(verifyPresentation(vpPoP, tIssuer, { now: 2000, requireHolderProof: true, holderKeys: { ed: holder.ed.publicKey, mldsa: holder.mldsa.publicKey }, expectedNonce: 'chal-xyz' }).verified === true, 'holder proof-of-possession verifies (presenter controls subject DID)');
  ok(verifyPresentation(present(vc, hrec, ['country']), tIssuer, { now: 2000, requireHolderProof: true, holderKeys: { ed: holder.ed.publicKey, mldsa: holder.mldsa.publicKey } }).verified === false, 'requireHolderProof with no holder proof -> FAILS');

  // hybrid SLH 3rd leg
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(7));
  const issuer3 = { ed: issuer.ed, mldsa: issuer.mldsa, slh };
  const tIssuer3 = { ed: tIssuer.ed, mldsa: tIssuer.mldsa, slh: slh.publicKey };
  const vc3 = issueCredential({ issuerKeys: issuer3, subjectDid, id: 'urn:vc:3', claims: { role: 'admin' } }).vc;
  ok(typeof vc3.proof.slh_sig === 'string' && verifyCredential(vc3, tIssuer3, { now: 1 }).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH-DSA) credential verifies');
  const vc3s = JSON.parse(JSON.stringify(vc3)); vc3s.proof.slh_sig = '00';
  ok(verifyCredential(vc3s, tIssuer3, { now: 1 }).verified === false, 'stripped SLH leg fails when issuer.slh pinned (anti-downgrade)');

  // W3C-VC interop: export to the standard shape, verify the round-trip, and prove tampering a W3C field fails
  const w3c = toW3CCredential(vc, { name: 'Ada Lovelace', over18: true, country: 'CH', clearance: 'secret' });
  ok(w3c['@context'][0] === 'https://www.w3.org/ns/credentials/v2' && w3c.credentialSubject.id === subjectDid && w3c.proof.type === 'TrelyanHybrid2026', 'W3C export has the standard VC shape + TrelyanHybrid proof');
  ok(verifyW3CCredential(w3c, tIssuer, { now: 2000 }).verified === true, 'W3C-exported credential verifies (round-trip) under the pinned issuer');
  const w3cT = JSON.parse(JSON.stringify(w3c)); w3cT.credentialSubject.id = makeDid(issuer);
  ok(verifyW3CCredential(w3cT, tIssuer, { now: 2000 }).verified === false, 'tampered W3C subject -> verify FAILS');
  const w3cE = JSON.parse(JSON.stringify(w3c)); w3cE.validUntil = 999999;
  ok(verifyW3CCredential(w3cE, tIssuer, { now: 2000 }).verified === false, 'tampered W3C validUntil (extend expiry) -> verify FAILS');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { vc: {} }]) { try { if (verifyCredential(bad, tIssuer).verified !== false) total = false; if (verifyPresentation(bad, tIssuer).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed creds/presentations -> verified:false, never throws');

  console.log('pqvc self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqvc\.mjs$/.test(process.argv[1] || '')) selfTest();
