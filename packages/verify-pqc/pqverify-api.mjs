/*!
 * pqverify-api — hosted, stateless PUBLIC verification endpoint (reference, DRAFT, standalone). OWNER-GATED deploy.
 *
 * One uniform surface so anyone can verify a TRELYAN artifact WITHOUT installing the SDK: an Evidence Pack, a PQEF
 * bundle, a pqsign code-signing bundle, a PQ-TSA timestamp token, or a KT inclusion proof. Composes the already-
 * reviewed verifiers; adds nothing cryptographic. Pairs with the CBOM funnel: a buyer can paste their signed
 * Evidence Pack here and confirm it.
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

export const SUPPORTED = ['evidence-pack', 'pqef', 'sign-bundle', 'tst', 'tst-restamp', 'kt-inclusion'];
const NOTICE = 'PREVIEW — verification by @trelyan/verify-pqc (UNAUDITED reference crypto, not FIPS-140-3 validated). A verdict confirms cryptographic validity and reports the signer; TRUST requires YOU to pin the expected public key (trust.*). Not for production reliance until the third-party audit.';
const hexToU8 = (h) => { if (typeof h !== 'string' || h.length % 2) throw new Error('bad hex'); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return b; };

function wrap(type, verdict, pinned) {
  return { ok: true, type, pinned: !!pinned, verdict, notice: NOTICE + (pinned ? '' : ' [UNPINNED: no trusted key supplied — this is validity, not trust.]') };
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
  const pack = signEvidencePack(buildEvidencePack({ scan: scanFiles([{ name: 'x.js', text: 'RSA-2048; MD5;' }]), meta: { generated_ts: 1 } }), signer.secretKey, signer.publicKey);
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

  // 4. unknown type + garbage artifact -> fail-closed, never throws
  ok((await verify({ type: 'nope', artifact: {} })).ok === false, 'unknown type -> ok:false (supported list returned)');
  for (const g of [null, undefined, 0, 'x', [], { type: 'evidence-pack', artifact: { sig: 'zz' } }, { type: 'pqef', artifact: { statement: 5 } }]) {
    const r = await verify(g); ok(r && (r.ok === false || r.verdict), 'fail-closed on garbage: ' + String(JSON.stringify(g)).slice(0, 30));
  }

  console.log('pqverify-api self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqverify-api\.mjs$/.test(process.argv[1] || '')) selfTest();
