/*!
 * pqpki — hybrid post-quantum certificate authority (reference, DRAFT, standalone).
 *
 * Top-10 product #3 (the PKI leg). A reference PQ CA that issues HYBRID certificates: each cert binds the subject's
 * CLASSICAL key (Ed25519) AND its POST-QUANTUM key (ML-DSA-87) together, and is signed by the CA with BOTH families
 * (ML-DSA-87 load-bearing + Ed25519 for classical-verifier interop). Because both subject keys are inside the one
 * CA-signed object, an on-path attacker cannot "strip the PQ key" without breaking the CA signature. Supports a CA →
 * intermediate → leaf chain and a signed revocation list (CRL).
 *
 * HONEST LIMITS (incl. full 11-seat council): certificates are canonical-JSON, NOT ASN.1/X.509 DER (no DER/OIDs,
 * NO NAME CONSTRAINTS, no extended-key-usage) — `is_ca` is the only cert-signing authority flag, `path_len` is
 * enforced (leaf-indexed). This is NOT an accredited eIDAS QTSP and issues NON-QUALIFIED certs; the on-the-wire
 * format aligns in spirit with the IETF LAMPS COMPOSITE-SIGNATURE direction (draft-ietf-lamps-pq-composite-sigs,
 * RFC 9958, draft-reddy-lamps-x509-pq-commit) but is NOT those standards and must not claim X.509/CABF/eIDAS interop.
 * Serial-number uniqueness is the ISSUER's responsibility (use random >=64-bit or a monotonic counter). Hybrid =
 * AND-composition (BOTH ML-DSA-87 + Ed25519 must verify): max security, but a future Ed25519 break would require
 * tampering to INVALIDATE (a MITM DoS, not a forgery). The CA's own key should live in a KT log (pqkt). Reference,
 * unaudited. Pass times explicitly (no wall-clock). Self-test: node pqpki.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

const CERT_CTX = utf8ToBytes('trelyan-pqpki-cert-v1');
const CRL_CTX = utf8ToBytes('trelyan-pqpki-crl-v1');
// Ed25519 (RFC-8032) has NO native context param, so we DOMAIN-SEPARATE the classical leg by binding the context into
// its pre-image: ed signs/verifies over `context ‖ 0x00 ‖ canon(tbs)` (council HIGH finding). With AND-composition
// (both legs required), this means neither the ML-DSA NOR the Ed25519 signature is a cross-protocol-reusable artifact.
const edDomMsg = (ctx, msg) => concatBytes(ctx, Uint8Array.of(0), msg);
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const kid = (mldsaPub) => bytesToHex(sha512(mldsaPub)).slice(0, 32); // key id = first 16 bytes of SHA-512(ML-DSA pub)

// a CA / subject identity = a hybrid keypair (Ed25519 classical + ML-DSA-87 PQ)
export function generateIdentity(seed) {
  const pqSeed = seed || ml_dsa87.keygen().secretKey.slice(0, 32);
  const pq = ml_dsa87.keygen(seed ? seed : undefined);
  const edSk = ed25519.utils.randomSecretKey ? ed25519.utils.randomSecretKey() : ed25519.utils.randomPrivateKey();
  return { pq, ed: { secretKey: edSk, publicKey: ed25519.getPublicKey(edSk) } };
}
export function pubOf(id) { return { kid: kid(id.pq.publicKey), mldsa_pub: bytesToHex(id.pq.publicKey), ed_pub: bytesToHex(id.ed.publicKey) }; }

/* ---------- issue a hybrid certificate ---------- */
// caCert = the issuer's own cert (null => self-signed root). Binds subject.{mldsa_pub, ed_pub} + validity + basic constraints.
export function issueCert({ subject, subjectPub, ca, caCert, serial, notBefore, notAfter, isCA = false, pathLen = null }) {
  const tbs = { // "to be signed"
    v: '0.1', serial: String(serial), subject, subject_kid: subjectPub.kid,
    subject_mldsa_pub: subjectPub.mldsa_pub, subject_ed_pub: subjectPub.ed_pub,
    issuer: caCert ? caCert.tbs.subject : subject, issuer_kid: caCert ? caCert.tbs.subject_kid : subjectPub.kid,
    not_before: notBefore ?? null, not_after: notAfter ?? null,
    basic_constraints: { is_ca: !!isCA, path_len: pathLen }, sig_alg: 'ML-DSA-87+Ed25519(hybrid)',
  };
  const msg = utf8ToBytes(canon(tbs));
  return { tbs, signatures: {
    mldsa: bytesToHex(ml_dsa87.sign(msg, ca.pq.secretKey, { context: CERT_CTX })),
    ed: bytesToHex(ed25519.sign(edDomMsg(CERT_CTX, msg), ca.ed.secretKey)), // context bound into the Ed25519 pre-image
  } };
}
export const selfSign = ({ subject, ca, serial, notBefore, notAfter, pathLen = null }) =>
  issueCert({ subject, subjectPub: pubOf(ca), ca, caCert: null, serial, notBefore, notAfter, isCA: true, pathLen });

/* ---------- verify a single cert against a (trusted or chain) issuer ---------- */
// issuerPub = { mldsa_pub, ed_pub } of the signer. at = current time for the validity window.
export function verifyCert(cert, issuerPub, opts = {}) {
 try { // TOTAL (fuzz): wraps guard+body so a throwing getter/Proxy/BigInt field fails CLOSED, never DoS
  if (!cert || typeof cert !== 'object' || !cert.tbs || typeof cert.tbs !== 'object' || !cert.signatures) return { verified: false, mldsaOk: false, edOk: false, timeOk: false, reason: 'malformed cert' };
  const msg = utf8ToBytes(canon(cert.tbs));
  let mldsaOk = false, edOk = false;
  try { mldsaOk = ml_dsa87.verify(hexToBytes(cert.signatures.mldsa), msg, hexToBytes(issuerPub.mldsa_pub), { context: CERT_CTX }); } catch { mldsaOk = false; }
  try { edOk = ed25519.verify(hexToBytes(cert.signatures.ed), edDomMsg(CERT_CTX, msg), hexToBytes(issuerPub.ed_pub)); } catch { edOk = false; }
  const at = opts.at;
  const timeOk = at == null || ((cert.tbs.not_before == null || at >= cert.tbs.not_before) && (cert.tbs.not_after == null || at <= cert.tbs.not_after));
  // ML-DSA is load-bearing (must verify); Ed25519 must ALSO verify when present (hybrid = both, defeats strip).
  const verified = mldsaOk && edOk && timeOk;
  return { verified, mldsaOk, edOk, timeOk, reason: !mldsaOk ? 'PQ (ML-DSA-87) signature invalid' : !edOk ? 'classical (Ed25519) signature invalid' : !timeOk ? 'outside validity window' : 'ok' };
 } catch { return { verified: false, mldsaOk: false, edOk: false, timeOk: false, reason: 'malformed cert' }; }
}

/* ---------- verify a chain: leaf -> ... -> trusted root (pinned) ---------- */
// chain = [leaf, intermediate, ..., root]; trustedRootPub = pinned root issuer pub. Enforces CA flag + path length.
export function verifyChain(chain, trustedRootPub, opts = {}) {
 try { // TOTAL (fuzz): a throwing getter/Proxy in any chain element fails CLOSED, never DoS
  if (!Array.isArray(chain) || !chain.length) return { verified: false, reason: 'empty chain' };
  // DEFENSE-IN-DEPTH (Moonshot): every cert's subject_kid MUST bind its own subject key — re-derive, don't trust the
  // stored value. (The verify key is taken from subject_mldsa_pub, so this also prevents kid/linkage confusion.)
  for (let j = 0; j < chain.length; j++) {
    try { if (chain[j].tbs.subject_kid !== kid(hexToBytes(chain[j].tbs.subject_mldsa_pub))) return { verified: false, at: j, reason: 'subject_kid at ' + j + ' does not bind the subject key' }; }
    catch { return { verified: false, at: j, reason: 'malformed cert at ' + j }; }
  }
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    const isLast = i === chain.length - 1;
    const issuerPub = isLast ? trustedRootPub : { mldsa_pub: chain[i + 1].tbs.subject_mldsa_pub, ed_pub: chain[i + 1].tbs.subject_ed_pub };
    const r = verifyCert(cert, issuerPub, opts);
    if (!r.verified) return { verified: false, at: i, reason: 'cert ' + i + ': ' + r.reason };
    if (!isLast) { // the issuer (next up) must be a CA (is_ca = keyCertSign authority here), and this cert's named issuer
      const up = chain[i + 1];
      if (!up.tbs.basic_constraints.is_ca) return { verified: false, at: i + 1, reason: 'issuer ' + (i + 1) + ' is not a CA (no cert-signing authority)' };
      if (cert.tbs.issuer_kid !== up.tbs.subject_kid) return { verified: false, at: i, reason: 'issuer_kid mismatch at ' + i + ' (chain not linked)' };
      // RFC-5280 pathLenConstraint: max non-self-issued intermediate CAs that may FOLLOW the issuer toward the leaf.
      // Chain is leaf-indexed (leaf=0); the intermediates below issuer (i+1) number exactly `i` => enforce i <= pl.
      const pl = up.tbs.basic_constraints.path_len;
      if (pl != null && i > pl) return { verified: false, at: i + 1, reason: 'path_len exceeded at issuer ' + (i + 1) + ' (>' + pl + ' intermediates below)' };
    }
  }
  // the top of the chain must BE the pinned root (subject == trusted root) AND be a CA (trust anchor consistency)
  const root = chain[chain.length - 1];
  if (root.tbs.subject_mldsa_pub !== trustedRootPub.mldsa_pub) return { verified: false, reason: 'chain does not terminate at the pinned root' };
  if (!root.tbs.basic_constraints.is_ca) return { verified: false, reason: 'pinned root is not a CA' };
  return { verified: true, reason: 'chain verified to the pinned root' };
 } catch { return { verified: false, reason: 'malformed chain' }; }
}

/* ---------- signed revocation list (with FRESHNESS — OpenAI/DeepSeek) ---------- */
// this_update/next_update bound the CRL's validity so a relying party rejects a STALE signed CRL (replay that would
// hide later revocations). crl_number is monotonic (anti-rollback). Set both for any security-relevant use.
export function makeCRL({ revoked, number, thisUpdate, nextUpdate, ts }, ca) {
  const tbs = { v: '0.1', issuer_kid: pubOf(ca).kid, crl_number: number ?? 0, this_update: thisUpdate ?? null, next_update: nextUpdate ?? null, ts: ts ?? null, revoked: (revoked || []).slice().sort() };
  return { tbs, sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(tbs)), ca.pq.secretKey, { context: CRL_CTX })) };
}
// opts.at = current time → enforces this_update <= at <= next_update. opts.minCrlNumber → anti-rollback (reject a
// CRL older than the highest seen). `usable` is the field a relying party should gate on (valid AND fresh).
export function checkRevocation(crl, caPub, serial, opts = {}) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt fails CLOSED, never DoS
  if (!crl || typeof crl !== 'object' || !crl.tbs || typeof crl.tbs !== 'object' || !Array.isArray(crl.tbs.revoked)) return { crl_valid: false, fresh: false, notRolledBack: false, usable: false, revoked: false, reason: 'malformed CRL' };
  let sigOk = false;
  try { sigOk = ml_dsa87.verify(hexToBytes(crl.sig), utf8ToBytes(canon(crl.tbs)), hexToBytes(caPub.mldsa_pub), { context: CRL_CTX }); } catch { sigOk = false; }
  const at = opts.at;
  const fresh = at == null || crl.tbs.next_update == null ? true : (at >= (crl.tbs.this_update ?? -Infinity) && at <= crl.tbs.next_update);
  const notRolledBack = opts.minCrlNumber == null || crl.tbs.crl_number >= opts.minCrlNumber;
  const usable = sigOk && fresh && notRolledBack;
  return { crl_valid: sigOk, fresh, notRolledBack, usable, revoked: usable && crl.tbs.revoked.includes(String(serial)),
    reason: !sigOk ? 'CRL signature invalid' : !fresh ? 'CRL STALE (outside this_update..next_update) — fetch a fresh CRL; fail closed for high assurance' : !notRolledBack ? 'CRL rolled back (number < highest seen)' : 'ok' };
 } catch { return { crl_valid: false, fresh: false, notRolledBack: false, usable: false, revoked: false, reason: 'malformed CRL' }; }
}

/* ---------- self-test: node pqpki.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const root = generateIdentity(new Uint8Array(32).fill(1));
  const inter = generateIdentity(new Uint8Array(32).fill(2));
  const leaf = generateIdentity(new Uint8Array(32).fill(3));
  const rootPub = pubOf(root);

  const rootCert = selfSign({ subject: 'TRELYAN Root CA', ca: root, serial: 1, notBefore: 0, notAfter: 10000, pathLen: 1 });
  const interCert = issueCert({ subject: 'TRELYAN Issuing CA', subjectPub: pubOf(inter), ca: root, caCert: rootCert, serial: 2, notBefore: 0, notAfter: 9000, isCA: true, pathLen: 0 });
  const leafCert = issueCert({ subject: 'svc.trelyan.dev', subjectPub: pubOf(leaf), ca: inter, caCert: interCert, serial: 3, notBefore: 0, notAfter: 8000 });

  // 1. single-cert verify (leaf under intermediate) — both sig families + window
  ok(verifyCert(leafCert, pubOf(inter), { at: 1000 }).verified === true, 'leaf verifies under the intermediate (hybrid sig + window)');
  ok(verifyCert(rootCert, rootPub, { at: 1000 }).verified === true, 'self-signed root verifies under its own key');

  // 2. the cert binds BOTH subject keys (strip-resistance): tamper the PQ pub -> signature fails
  const stripped = JSON.parse(JSON.stringify(leafCert)); stripped.tbs.subject_mldsa_pub = '00'.repeat(32);
  ok(verifyCert(stripped, pubOf(inter), { at: 1000 }).verified === false, 'altering the bound PQ key -> cert FAILS (PQ key cannot be stripped/swapped)');

  // 3. expired / not-yet-valid
  ok(verifyCert(leafCert, pubOf(inter), { at: 9999 }).timeOk === false, 'leaf outside its validity window -> timeOk false');

  // 4. hybrid: a broken classical sig also fails (both must verify)
  const edBad = JSON.parse(JSON.stringify(leafCert)); edBad.signatures.ed = edBad.signatures.ed.slice(0, -2) + (edBad.signatures.ed.endsWith('00') ? '11' : '00');
  ok(verifyCert(edBad, pubOf(inter), { at: 1000 }).verified === false, 'broken Ed25519 leg -> hybrid verify FAILS (both families required)');

  // 5. full chain leaf -> inter -> root, pinned root
  ok(verifyChain([leafCert, interCert, rootCert], rootPub, { at: 1000 }).verified === true, 'chain leaf->inter->root verifies to the pinned root');
  // wrong pinned root -> fail
  ok(verifyChain([leafCert, interCert, rootCert], pubOf(generateIdentity(new Uint8Array(32).fill(9))), { at: 1000 }).verified === false, 'chain under a non-pinned root -> FAILS');
  // a non-CA cannot be an issuer: re-issue leaf as if from the leaf (not a CA)
  const fakeIssued = issueCert({ subject: 'evil', subjectPub: pubOf(generateIdentity(new Uint8Array(32).fill(7))), ca: leaf, caCert: leafCert, serial: 99, notBefore: 0, notAfter: 8000 });
  ok(verifyChain([fakeIssued, leafCert, interCert, rootCert], rootPub, { at: 1000 }).verified === false, 'a non-CA leaf used as an issuer -> chain FAILS (basic constraints)');

  // 6. path_len ENFORCEMENT (Grok): inter has path_len 0, so it may NOT have an intermediate CA beneath it
  const inter2 = generateIdentity(new Uint8Array(32).fill(4));
  const inter2Cert = issueCert({ subject: 'rogue sub-CA', subjectPub: pubOf(inter2), ca: inter, caCert: interCert, serial: 4, notBefore: 0, notAfter: 8000, isCA: true });
  const leaf2 = generateIdentity(new Uint8Array(32).fill(5));
  const leaf2Cert = issueCert({ subject: 'x', subjectPub: pubOf(leaf2), ca: inter2, caCert: inter2Cert, serial: 5, notBefore: 0, notAfter: 8000 });
  const plRes = verifyChain([leaf2Cert, inter2Cert, interCert, rootCert], rootPub, { at: 1000 });
  ok(plRes.verified === false && /path_len/.test(plRes.reason), 'path_len ENFORCED: a sub-CA beneath a path_len-0 intermediate -> chain FAILS');
  // a non-CA pinned root is rejected (trust-anchor must be a CA)
  const notCaRoot = issueCert({ subject: 'not-a-ca', subjectPub: pubOf(leaf), ca: leaf, caCert: null, serial: 1, notBefore: 0, notAfter: 8000, isCA: false });
  ok(verifyChain([notCaRoot], pubOf(leaf), { at: 1000 }).verified === false, 'a non-CA pinned root -> chain FAILS (trust-anchor consistency)');

  // 7. revocation (with FRESHNESS)
  const crl = makeCRL({ revoked: ['3'], number: 1, thisUpdate: 1400, nextUpdate: 1600, ts: 1500 }, inter);
  ok(checkRevocation(crl, pubOf(inter), 3, { at: 1500 }).revoked === true, 'revoked serial reported revoked under a fresh CRL');
  ok(checkRevocation(crl, pubOf(inter), 2, { at: 1500 }).revoked === false, 'non-revoked serial -> not revoked');
  ok(checkRevocation(crl, rootPub, 3, { at: 1500 }).crl_valid === false, 'CRL under a wrong issuer key -> crl_valid false');
  // STALE-CRL replay is rejected (OpenAI/DeepSeek fix): at past next_update -> not fresh, not usable
  const stale = checkRevocation(crl, pubOf(inter), 3, { at: 5000 });
  ok(stale.fresh === false && stale.usable === false, 'STALE CRL (at > next_update) -> not usable (stale-replay defeated)');
  // anti-rollback: a CRL older than the highest seen is rejected
  ok(checkRevocation(crl, pubOf(inter), 3, { at: 1500, minCrlNumber: 5 }).notRolledBack === false, 'CRL rolled back (number < highest seen) -> rejected');

  // 8. kid re-binding (Moonshot): a cert whose subject_kid does not match its key -> chain FAILS
  const kidTamper = JSON.parse(JSON.stringify(leafCert)); kidTamper.tbs.subject_kid = 'deadbeef'.repeat(4);
  ok(verifyChain([kidTamper, interCert, rootCert], rootPub, { at: 1000 }).reason.includes('subject_kid'), 'a cert whose subject_kid does not bind its key -> chain FAILS');

  console.log('pqpki self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqpki\.mjs$/.test(process.argv[1] || '')) selfTest();
