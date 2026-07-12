/*!
 * pqverify-api — hosted, stateless PUBLIC verification endpoint (reference, DRAFT, standalone). OWNER-GATED deploy.
 *
 * One uniform surface so anyone can verify a TRELYAN artifact WITHOUT installing the SDK: an Evidence Pack, a PQEF
 * bundle, a pqsign code-signing bundle, a PQ-TSA timestamp token, a KT inclusion proof, and the Wave-2 product
 * artifacts (TRELYANShield report, agent capability, app-admission cert, consent receipt, verifiable credential,
 * firmware manifest, payment authorization). Composes the already-reviewed verifiers; adds nothing cryptographic.
 * Pairs with the CBOM funnel: a buyer can paste their signed Evidence Pack here and confirm it.
 *
 * HONEST TRUST MODEL (the important part): a verdict confirms CRYPTOGRAPHIC VALIDITY and REPORTS who signed — it does
 * NOT decide trust for you. "verified:true" WITHOUT a pinned key means "internally consistent / self-attested", not
 * "you trust the signer". Supply the expected public key (trust.*) to PIN. Stateless, fail-closed, total (never
 * throws on garbage). UNAUDITED reference crypto — not for production reliance until the third-party audit.
 * Self-test: node pqverify-api.mjs
 */
import { verifyEvidencePack } from './pqcbom-report.mjs';
import { verifyPQEFBundle } from './pqef.mjs';
import { verifyBundle as verifySignBundle } from './pqsign.mjs';
import { verifyTimestamp, verifyRestamp } from './pqtsa.mjs';
import { verifyKeyEventInclusion } from './pqkt.mjs';
import { verifyShieldReport } from './pqshield.mjs';
import { verifyCapability } from './pqcap.mjs';
import { verifyAdmission } from './pqadmit.mjs';
import { verifyConsent } from './pqconsent.mjs';
import { verifyCredential } from './pqvc.mjs';
import { verifyFirmware } from './pqfirmware.mjs';
import { verifyAuthorization } from './pqpay.mjs';

export const SUPPORTED = ['evidence-pack', 'pqef', 'sign-bundle', 'tst', 'tst-restamp', 'kt-inclusion',
  'shield-report', 'capability', 'app-cert', 'consent-receipt', 'credential', 'firmware', 'payment-auth'];
const NOTICE = 'PREVIEW — verification by @trelyan/verify-pqc (UNAUDITED reference crypto, not FIPS-140-3 validated). A verdict confirms cryptographic validity and reports the signer; TRUST requires YOU to pin the expected public key (trust.*). Not for production reliance until the third-party audit.';
const hexToU8 = (h) => { if (typeof h !== 'string' || h.length % 2) throw new Error('bad hex'); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return b; };
// build a pinned HYBRID key { ed, mldsa[, slh] } from the trust block (Wave-2 cores); null if ed+mldsa absent.
function hybrid(tr) { if (!tr.ed_pub_hex || !tr.mldsa_pub_hex) return null; const k = { ed: hexToU8(tr.ed_pub_hex), mldsa: hexToU8(tr.mldsa_pub_hex) }; if (tr.slh_pub_hex) k.slh = hexToU8(tr.slh_pub_hex); return k; }
const arrToSet = (x) => (Array.isArray(x) ? { has: (id) => x.includes(id) } : (x && typeof x.has === 'function' ? x : undefined));
const NEED_HYBRID = 'requires a pinned hybrid key: trust.ed_pub_hex + trust.mldsa_pub_hex (+ optional trust.slh_pub_hex)';

function wrap(type, verdict, pinned, caveat) {
  return { ok: true, type, pinned: !!pinned, verdict, ...(caveat ? { caveat } : {}), notice: NOTICE + (pinned ? '' : ' [UNPINNED: no trusted key supplied — this is validity, not trust.]') };
}
const err = (msg) => ({ ok: false, error: msg, supported: SUPPORTED, notice: NOTICE });

// the dispatcher. request = { type, artifact, trust:{ signer_pub_hex?, log_pub_hex?, tsa_pub_hex?, expectedTranscript?, trustedIssuers? } }
export async function verify(request) {
  try {
    const t = request && request.type, a = request && request.artifact, tr = (request && request.trust) || {};
    if (!SUPPORTED.includes(t)) return err('unknown/missing type: ' + JSON.stringify(t));
    if (a == null || typeof a !== 'object') return err('missing artifact object');
    switch (t) {
      case 'evidence-pack': {
        const pin = tr.signer_pub_hex ? hexToU8(tr.signer_pub_hex) : undefined;
        return wrap(t, verifyEvidencePack(a, pin), !!pin);
      }
      case 'pqef': {
        const r = await verifyPQEFBundle(a, { trustedIssuers: tr.trustedIssuers || [] });
        return wrap(t, r, (tr.trustedIssuers || []).length > 0);
      }
      case 'sign-bundle': {
        if (!tr.signer_pub_hex || !tr.log_pub_hex) return err('sign-bundle requires trust.signer_pub_hex + trust.log_pub_hex (pin both)');
        return wrap(t, verifySignBundle(a, hexToU8(tr.signer_pub_hex), hexToU8(tr.log_pub_hex)), true);
      }
      case 'tst': {
        const pin = tr.tsa_pub_hex ? hexToU8(tr.tsa_pub_hex) : undefined;
        return wrap(t, verifyTimestamp(a, pin), !!pin);
      }
      case 'tst-restamp': {
        const pin = tr.tsa_pub_hex ? hexToU8(tr.tsa_pub_hex) : undefined;
        return wrap(t, verifyRestamp(a, pin, { expectedBundle: tr.expectedBundle }), !!pin);
      }
      case 'kt-inclusion': {
        if (!tr.log_pub_hex) return err('kt-inclusion requires trust.log_pub_hex (pin the log key)');
        return wrap(t, verifyKeyEventInclusion(a, hexToU8(tr.log_pub_hex)), true);
      }
      case 'shield-report': { const k = hybrid(tr); if (!k) return err('shield-report ' + NEED_HYBRID); return wrap(t, verifyShieldReport(a, k, { now: tr.now, expectedAnchor: tr.expectedAnchor }), true); }
      case 'capability': { const k = hybrid(tr); if (!k) return err('capability ' + NEED_HYBRID);
        // honest caveats (apex sweep 1 Jul): (1) scope unchecked if no request; (2) a use-limited (max_uses) token's
        // replay/use-limit is NOT enforced here (allowUnmeteredCheck:true) — the gateway MUST meter the nonce in a durable
        // ledger (verifyAndConsume). Mirrors payment-auth so a verdict never silently over-claims a use-limited token.
        const capCav = [(a && a.max_uses != null) ? 'use-limited token: max_uses/replay is NOT enforced here — the gateway must meter the nonce in a durable ledger (verifyAndConsume)' : null, tr.request ? null : 'token validity only — no request supplied to scope-check'].filter(Boolean).join('; ') || undefined;
        return wrap(t, verifyCapability(a, k, { request: tr.request, now: tr.now, audience: tr.audience, holderProof: tr.holderProof, challenge: tr.challenge, requireHolderProof: !!tr.holderProof, allowUnmeteredCheck: true }), true, capCav); }
      case 'app-cert': { const k = hybrid(tr); if (!k) return err('app-cert ' + NEED_HYBRID); const bytes = tr.artifact_hex ? hexToU8(tr.artifact_hex) : undefined; if (!bytes && tr.allowUnboundArtifact !== true) return err('app-cert: supply trust.artifact_hex to bind the deployed binary, or set trust.allowUnboundArtifact:true for an explicit metadata-only check'); return wrap(t, verifyAdmission(a, k, { artifactBytes: bytes, allowUnboundArtifact: !bytes, now: tr.now, minCertLevel: tr.minCertLevel, minVersion: tr.minVersion, revoked: arrToSet(tr.revoked) }), true, bytes ? undefined : 'metadata-only — the deployed binary is NOT bound here; the deploy gate must bind it'); }
      case 'consent-receipt': { return wrap(t, verifyConsent(a, { now: tr.now, controller: tr.controller, purpose: tr.purpose, category: tr.category, revoked: arrToSet(tr.revoked) }), false, 'self-sovereign: the data subject self-signs — there is NO external key to pin (pinned:false), so this confirms the subject signed their own consent (evidence), NOT third-party-verifiable trust or legal validity'); }
      case 'credential': { const k = hybrid(tr); if (!k) return err('credential ' + NEED_HYBRID); return wrap(t, verifyCredential(a, k, { now: tr.now, revoked: tr.revoked }), true); }
      case 'firmware': { const k = hybrid(tr); if (!k) return err('firmware ' + NEED_HYBRID); const bytes = tr.artifact_hex ? hexToU8(tr.artifact_hex) : undefined; if (!bytes && tr.allowUnboundArtifact !== true) return err('firmware: supply trust.artifact_hex to bind the flashed binary, or set trust.allowUnboundArtifact:true for an explicit metadata-only check'); return wrap(t, verifyFirmware(a, k, { artifactBytes: bytes, allowUnboundArtifact: !bytes, currentVersion: tr.currentVersion, deviceModel: tr.deviceModel }), true, bytes ? undefined : 'metadata-only — the firmware binary is NOT bound here; the device must bind it before flashing'); }
      case 'payment-auth': { const k = hybrid(tr); if (!k) return err('payment-auth ' + NEED_HYBRID); return wrap(t, verifyAuthorization(a, k, { now: tr.now, maxAmount: tr.maxAmount, expectedPayee: tr.expectedPayee, expectedCurrency: tr.expectedCurrency, allowUnmeteredCheck: true }), true, 'validity-only — replay is NOT enforced here; the processor must consume the nonce in a durable ledger'); }
      default: return err('unhandled type');
    }
  } catch (e) { return err('verify error: ' + String((e && e.message) || e)); }
}

// node http adapter (demo): POST { type, artifact, trust } -> JSON verdict. Production = serverless fn (owner deploy).
export function nodeHandler() {
  return (req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 8_000_000) req.destroy(); });
    req.on('end', async () => {
      res.setHeader('content-type', 'application/json');
      try { res.end(JSON.stringify(await verify(JSON.parse(body || '{}')))); }
      catch (e) { res.statusCode = 400; res.end(JSON.stringify(err('bad JSON: ' + String((e && e.message) || e)))); }
    });
  };
}

/* ---------- self-test: node pqverify-api.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { bytesToHex } = await import('@noble/hashes/utils.js');
  const { scanFiles } = await import('./pqcbom.mjs');
  const { buildEvidencePack, signEvidencePack } = await import('./pqcbom-report.mjs');
  const { PQTransparencyLog, signArtifact } = await import('./pqsign.mjs');
  const { genTsaKey, timestamp } = await import('./pqtsa.mjs');

  // 1. Evidence Pack: pinned -> verified; unpinned -> validity-only flag; wrong key -> false
  const signer = ml_dsa87.keygen(new Uint8Array(32).fill(41));
  const pack = signEvidencePack(buildEvidencePack({ scan: scanFiles([{ name: 'x.js', text: 'RSA-2048; MD5;' }]), meta: { generated_ts: 1 } }), signer.secretKey, signer.publicKey); // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
  const ep = await verify({ type: 'evidence-pack', artifact: pack, trust: { signer_pub_hex: bytesToHex(signer.publicKey) } });
  ok(ep.ok && ep.pinned && ep.verdict.verified === true, 'evidence-pack verifies under a pinned signer key');
  const epU = await verify({ type: 'evidence-pack', artifact: pack });
  ok(epU.ok && epU.pinned === false && /UNPINNED/.test(epU.notice), 'unpinned evidence-pack -> validity-only, UNPINNED notice');
  const epW = await verify({ type: 'evidence-pack', artifact: pack, trust: { signer_pub_hex: bytesToHex(ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey) } });
  ok(epW.verdict.verified === false, 'evidence-pack under a wrong pinned key -> NOT verified');

  // 2. sign-bundle: requires both keys; verifies a real bundle
  const sk = ml_dsa87.keygen(new Uint8Array(32).fill(42)), lk = ml_dsa87.keygen(new Uint8Array(32).fill(43));
  const log = new PQTransparencyLog(); const att = signArtifact(new TextEncoder().encode('v1.0 binary'), sk.secretKey, { name: 'cli' }, { ts: 1 });
  log.append(att); const sth = log.signedTreeHead(lk.secretKey, { ts: 2 }); const inc = log.inclusion(0);
  const sb = await verify({ type: 'sign-bundle', artifact: { att, inclusion: inc, sth }, trust: { signer_pub_hex: bytesToHex(sk.publicKey), log_pub_hex: bytesToHex(lk.publicKey) } });
  ok(sb.ok && sb.verdict.verified === true, 'sign-bundle verifies under pinned signer + log keys');
  ok((await verify({ type: 'sign-bundle', artifact: { att, inclusion: inc, sth } })).ok === false, 'sign-bundle without pinned keys -> error (must pin)');

  // 3. TST
  const tsa = genTsaKey(new Uint8Array(32).fill(44));
  const tst = timestamp({ content_sha256: 'ab'.repeat(32) }, tsa.secretKey, tsa.publicKey, { ts: 1 });
  ok((await verify({ type: 'tst', artifact: tst, trust: { tsa_pub_hex: bytesToHex(tsa.publicKey) } })).verdict.verified === true, 'tst verifies under a pinned TSA key');

  // 4b. Wave-2 cores: verify via the hosted surface under a pinned hybrid key (+ a negative per type)
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { createShieldReport } = await import('./pqshield.mjs');
  const { signFirmware } = await import('./pqfirmware.mjs');
  const { issueCredential, makeDid } = await import('./pqvc.mjs');
  const { issueCapability } = await import('./pqcap.mjs');
  const { issueAppCert } = await import('./pqadmit.mjs');
  const { grantConsent } = await import('./pqconsent.mjs');
  const { createAuthorization } = await import('./pqpay.mjs');
  const mkks = (e, m) => ({ ed: { secretKey: new Uint8Array(32).fill(e), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(e)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(m)) });
  const pubBytes = (ks) => ({ ed: ks.ed.publicKey, mldsa: ks.mldsa.publicKey });
  const tpub = (ks) => ({ ed_pub_hex: bytesToHex(ks.ed.publicKey), mldsa_pub_hex: bytesToHex(ks.mldsa.publicKey) });

  const shk = mkks(70, 71);
  const shrep = createShieldReport({ issuerKeys: shk, target: 'api', assets: [{ label: 'x', algorithm: 'RSA-2048', internet_facing: true }], generatedAt: 1 }); // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
  ok((await verify({ type: 'shield-report', artifact: shrep, trust: tpub(shk) })).verdict.verified === true, 'shield-report verifies under a pinned hybrid issuer');
  ok((await verify({ type: 'shield-report', artifact: shrep, trust: tpub(mkks(1, 2)) })).verdict.verified === false, 'shield-report under a wrong key -> not verified');
  ok((await verify({ type: 'shield-report', artifact: shrep })).ok === false, 'shield-report without a pinned hybrid key -> error (must pin)');

  const fwk = mkks(72, 73), fwb = new Uint8Array(64).fill(0x5a);
  const fwm = signFirmware({ vendorKeys: fwk, deviceModel: 'M', version: 3, buildId: 'b', artifactBytes: fwb });
  ok((await verify({ type: 'firmware', artifact: fwm, trust: { ...tpub(fwk), artifact_hex: bytesToHex(fwb), currentVersion: 2, deviceModel: 'M' } })).verdict.verified === true, 'firmware verifies (binary bound) under a pinned vendor');
  ok((await verify({ type: 'firmware', artifact: fwm, trust: { ...tpub(fwk), artifact_hex: bytesToHex(new Uint8Array(64).fill(9)), currentVersion: 2 } })).verdict.verified === false, 'firmware with a swapped binary -> not verified');

  const vik = mkks(74, 75), vsk = mkks(76, 77);
  const { vc: apivc } = issueCredential({ issuerKeys: vik, subjectDid: makeDid(pubBytes(vsk)), claims: { role: 'x' }, id: 'vc-api' });
  ok((await verify({ type: 'credential', artifact: apivc, trust: tpub(vik) })).verdict.verified === true, 'credential verifies under a pinned hybrid issuer');
  ok((await verify({ type: 'credential', artifact: apivc, trust: tpub(mkks(3, 4)) })).verdict.verified === false, 'credential under a wrong issuer -> not verified');

  const cik = mkks(78, 79), cak = mkks(80, 81);
  const cap = issueCapability({ issuerKeys: cik, agent: pubBytes(cak), tool: 'T', caveats: { arg_in: { op: ['read'] } }, nonce: 'api-cap' });
  ok((await verify({ type: 'capability', artifact: cap, trust: { ...tpub(cik), request: { tool: 'T', args: { op: 'read' } } } })).verdict.verified === true, 'capability verifies an in-scope request');
  ok((await verify({ type: 'capability', artifact: cap, trust: { ...tpub(cik), request: { tool: 'T', args: { op: 'write' } } } })).verdict.verified === false, 'capability rejects an out-of-scope request');
  // apex-sweep 1 Jul: a use-limited (max_uses) token verifies validity BUT the hosted surface does not meter it — the
  // verdict must DISCLOSE that (no silent over-claim), mirroring payment-auth's replay-not-enforced caveat.
  { const capU = issueCapability({ issuerKeys: cik, agent: pubBytes(cak), tool: 'T', caveats: { arg_in: { op: ['read'] } }, maxUses: 1, nonce: 'api-cap-u' });
    const r = await verify({ type: 'capability', artifact: capU, trust: { ...tpub(cik), request: { tool: 'T', args: { op: 'read' } } } });
    ok(r.verdict.verified === true && /max_uses\/replay is NOT enforced/.test(r.caveat || ''), 'apex-sweep: use-limited (max_uses) capability -> verified BUT carries the honest replay/use-limit-not-enforced caveat (no over-claim)'); }

  const aik = mkks(82, 83);
  const cert = issueAppCert({ issuerKeys: aik, app: 'acme/api', version: '1.0.0', artifactBytes: fwb, certLevel: 'SOVEREIGN_GOLD', checks: { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true } });
  ok((await verify({ type: 'app-cert', artifact: cert, trust: { ...tpub(aik), artifact_hex: bytesToHex(fwb) } })).verdict.verified === true, 'app-cert admits with the bound artifact under a pinned authority');
  ok((await verify({ type: 'app-cert', artifact: cert, trust: { ...tpub(aik), artifact_hex: bytesToHex(new Uint8Array(64).fill(9)) } })).verdict.verified === false, 'app-cert with a swapped artifact -> not admitted');
  ok((await verify({ type: 'app-cert', artifact: cert, trust: tpub(aik) })).ok === false, 'app-cert without artifact_hex AND without explicit opt-in -> error (no silent metadata-only)');
  { const r = await verify({ type: 'app-cert', artifact: cert, trust: { ...tpub(aik), allowUnboundArtifact: true } }); ok(r.verdict && r.verdict.verified === true && /metadata-only/.test(r.caveat || ''), 'app-cert explicit metadata-only opt-in -> verified + honest caveat'); }
  ok((await verify({ type: 'firmware', artifact: fwm, trust: tpub(fwk) })).ok === false, 'firmware without artifact_hex AND without explicit opt-in -> error (no silent metadata-only)');

  const ssk = mkks(84, 85);
  const rcpt = grantConsent({ subjectKeys: ssk, controller: 'vh', purposes: ['p1'], categories: ['c1'], legalBasis: 'GDPR-Art-9-2-a', nonce: 'api-n' });
  ok((await verify({ type: 'consent-receipt', artifact: rcpt, trust: { purpose: 'p1', category: 'c1' } })).verdict.verified === true, 'consent-receipt verifies an in-scope purpose (self-sovereign)');
  ok((await verify({ type: 'consent-receipt', artifact: rcpt, trust: { purpose: 'p2' } })).verdict.verified === false, 'consent-receipt rejects an ungranted purpose');
  ok((await verify({ type: 'consent-receipt', artifact: rcpt, trust: { purpose: 'p1', category: 'c1' } })).pinned === false, 'consent-receipt reports pinned:false (self-signed, no external key — honest pinned semantics)');
  ok((await verify({ type: 'shield-report', artifact: shrep, trust: tpub(shk) })).pinned === true, 'a real hybrid-pinned type reports pinned:true (pinned flag means a key WAS supplied + checked)');

  const pk = mkks(86, 87);
  const auth = createAuthorization({ payerKeys: pk, id: 'pay-api', payee: 'm', amount: 100, currency: 'USD', nonce: 'api-pay' });
  ok((await verify({ type: 'payment-auth', artifact: auth, trust: tpub(pk) })).verdict.verified === true, 'payment-auth verifies under a pinned payer (validity-only)');
  ok(/replay is NOT enforced/.test((await verify({ type: 'payment-auth', artifact: auth, trust: tpub(pk) })).caveat || ''), 'payment-auth carries the honest replay-not-enforced caveat');

  // 4. unknown type + garbage artifact -> fail-closed, never throws
  ok((await verify({ type: 'nope', artifact: {} })).ok === false, 'unknown type -> ok:false (supported list returned)');
  for (const g of [null, undefined, 0, 'x', [], { type: 'evidence-pack', artifact: { sig: 'zz' } }, { type: 'pqef', artifact: { statement: 5 } }]) {
    const r = await verify(g); ok(r && (r.ok === false || r.verdict), 'fail-closed on garbage: ' + String(JSON.stringify(g)).slice(0, 30));
  }

  console.log('pqverify-api self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqverify-api\.mjs$/.test(process.argv[1] || '')) selfTest();
