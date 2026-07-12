/*!
 * trelyan-console — unified TRELYAN product console (reference, DRAFT). ONE runnable surface for the portfolio: a
 * dashboard that lists the products and, for each user-facing product line, a REAL one-shot demo (sign → verify roundtrip
 * with the tested cores, using verified call shapes) plus the three richer tested services mounted under path prefixes.
 * Framework-free node:http, testable without sockets via handleRequest, embedded dashboard.
 *   /                       portfolio dashboard
 *   POST /api/shield/grade  TRELYANShield  — grade a crypto posture (A–F)
 *   POST /api/vc/issue      QuantumDNA     — issue + verify a verifiable credential
 *   POST /api/sign          PQ code-sign   — sign + verify an artifact attestation
 *   POST /api/firmware/sign QuantumShield  — sign + verify a firmware manifest (+ anti-rollback check)
 *   POST /api/consent/grant VaultHealth    — grant + verify a consent receipt (+ deny-by-default check)
 *   POST /api/cap/issue     ThrondarAgent  — issue + verify an agent capability token (+ out-of-bounds check)
 *   /omega/*  /mesh/*  /search/*           mounted omega-server / pqmesh-server / pqsearch-server (their tested handlers)
 *
 * HONEST: reference/DRAFT, unaudited COMPOSITION over the audited @noble crypto. Demos use 2-family signers (Ed25519 ∧
 * ML-DSA-87) for speed; production uses the 3-family pqseal AND-composition. No auth/persistence — a demo console, not
 * production hosting. Every underlying core's gate/claim-hygiene rule still holds. Run: node trelyan-console.mjs --serve 8080
 * Self-test: node trelyan-console.mjs
 */
import * as omegaServer from './omega-server.mjs';
import * as pqmeshServer from './pqmesh-server.mjs';
import * as pqsearchServer from './pqsearch-server.mjs';
import { classifyKex, classifyAuth, classifyTls, gradePosture } from './pqposture.mjs';
import { issueCredential, verifyCredential, makeDid } from './pqvc.mjs';
import { signArtifact, verifyArtifact } from './pqsign.mjs';
import { signFirmware, verifyFirmware } from './pqfirmware.mjs';
import { grantConsent, verifyConsent } from './pqconsent.mjs';
import { issueCapability, verifyCapability } from './pqcap.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

// deterministic 2-family demo signer per role (fast: no SLH). keys = full keypair; pubs = pinned pubkeys.
const keysFor = (() => {
  const cache = new Map();
  return (role) => {
    if (cache.has(role)) return cache.get(role);
    const seed = sha256(utf8ToBytes('trelyan-console-demo:' + role)).slice(0, 32);
    const edsk = seed;
    const k = { ed: { secretKey: edsk, publicKey: ed25519.getPublicKey(edsk) }, mldsa: ml_dsa87.keygen(seed) };
    cache.set(role, k); return k;
  };
})();
const pubs = (k) => ({ ed: k.ed.publicKey, mldsa: k.mldsa.publicKey });

// ---- real one-shot product demos (each returns the artifact + its verification, computed here with the tested core) ----
function shieldGrade({ kex = 'X25519MLKEM768', auth = 'ML-DSA-87', tls = 'TLSv1.3' } = {}) {
  const k = classifyKex(kex), a = classifyAuth(auth), t = classifyTls(tls);
  return { product: 'TRELYANShield', inputs: { kex, auth, tls }, grade: gradePosture({ kex: k, auth: a, tls: t, inconclusive: k.risk === 'inconclusive' }) };
}
function vcIssue({ subjectDid = 'did:example:alice', claims = { over18: true, country: 'US' } } = {}) {
  const issuer = keysFor('quantumdna-issuer');
  const { vc } = issueCredential({ issuerKeys: issuer, subjectDid, id: 'urn:vc:console-demo', claims });
  const v = verifyCredential(vc, pubs(issuer), { now: 1 });
  return { product: 'QuantumDNA', issuer_did: makeDid(issuer), vc: { id: vc.id, type: vc.type, subject: vc.subject, claims_root: vc.claims_root }, verified: v.verified };
}
function codeSign({ artifact = 'release-binary-v1.2.3', name = 'trelyan-cli', version = '1.2.3' } = {}) {
  const signer = keysFor('codesign').mldsa;   // pqsign uses a single ML-DSA-87 signer (secretKey/publicKey)
  const att = signArtifact(utf8ToBytes(String(artifact)), signer.secretKey, { name, version }, { ts: 1000 });
  return { product: 'PQ code-signing', meta: att.meta, verified: verifyArtifact(att, signer.publicKey) === true };
}
function firmwareSign({ deviceModel = 'TRLN-Sensor-A', version = 7, image = 'firmware-bytes-v7' } = {}) {
  const vendor = keysFor('firmware-vendor');
  const bin = utf8ToBytes(String(image));
  const m = signFirmware({ vendorKeys: vendor, deviceModel, version: Number(version), buildId: 'b-' + version, artifactBytes: bin, releasedAt: 1000 });
  const ok = verifyFirmware(m, pubs(vendor), { artifactBytes: bin, currentVersion: Number(version) - 1, deviceModel }).verified;
  const rollbackRejected = verifyFirmware(m, pubs(vendor), { artifactBytes: bin, currentVersion: Number(version) + 1, deviceModel }).verified === false;
  return { product: 'QuantumShield IoT', device: deviceModel, version: Number(version), verified: ok, anti_rollback_ok: rollbackRejected };
}
function consentGrant({ controller = 'vaulthealth', purposes = ['ai_coaching'], categories = ['HEART_RATE'] } = {}) {
  const subject = keysFor('consent-subject');
  const r = grantConsent({ subjectKeys: subject, controller, purposes, categories, legalBasis: 'GDPR-Art-9-2-a-explicit', jurisdiction: 'EU', expiresAt: 1000, nonce: 'c-console' });
  const granted = verifyConsent(r, { now: 1, controller, purpose: purposes[0], category: categories[0] }).verified;
  const ungrantedRejected = verifyConsent(r, { now: 1, controller, purpose: 'ad_targeting' }).verified === false;
  return { product: 'VaultHealth', receipt_id: r.receipt_id, granted_verified: granted, deny_by_default_ok: ungrantedRejected };
}
function capIssue({ tool = 'DatabaseQuery', scope = 'read-only' } = {}) {
  const principal = keysFor('cap-issuer');
  const agent = keysFor('cap-agent');
  const agentPub = pubs(agent);
  const tok = issueCapability({ issuerKeys: principal, agent: agentPub, tool, caveats: { arg_prefix: { table: 'public.' }, arg_max: { limit: 100 }, arg_in: { op: ['select'] } }, scope, expiresAt: 1000, audience: 'orch-1', nonce: 'cap-console' });
  const inBounds = verifyCapability(tok, pubs(principal), { request: { tool, args: { table: 'public.users', op: 'select', limit: 50 } }, now: 1, audience: 'orch-1' }).verified;
  const outOfBounds = verifyCapability(tok, pubs(principal), { request: { tool, args: { table: 'secret.keys', op: 'delete', limit: 9999 } }, now: 1, audience: 'orch-1' }).verified === false;
  return { product: 'ThrondarAgent', tool, in_bounds_verified: inBounds, out_of_bounds_rejected: outOfBounds };
}

const PRODUCTS = [
  { name: 'TRELYANShield', demo: '/api/shield/grade', what: 'grade a crypto posture A–F' },
  { name: 'QuantumDNA', demo: '/api/vc/issue', what: 'issue + verify a verifiable credential' },
  { name: 'PQ code-signing', demo: '/api/sign', what: 'sign + verify an artifact' },
  { name: 'QuantumShield IoT', demo: '/api/firmware/sign', what: 'sign firmware + anti-rollback' },
  { name: 'VaultHealth', demo: '/api/consent/grant', what: 'consent receipt + deny-by-default' },
  { name: 'ThrondarAgent', demo: '/api/cap/issue', what: 'agent capability + out-of-bounds reject' },
  { name: 'TRELYAN OMEGA', demo: '/omega/', what: 'capability manifest + evidence pack (mounted)' },
  { name: 'QuantumMesh', demo: '/mesh/', what: 'PQ messenger (mounted)' },
  { name: 'QDS-Ω', demo: '/search/', what: 'verifiable search (mounted)' },
];

/** handleRequest(method, path, body) — pure handler; returns { status, contentType, body }. */
export function handleRequest(method, path, body) {
  const json = (o, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(o) });
  const parse = () => (typeof body === 'string' ? JSON.parse(body || '{}') : (body || {}));
  try {
    // mount the three richer tested services under prefixes (delegate to their own handlers)
    for (const [prefix, mod] of [['/omega', omegaServer], ['/mesh', pqmeshServer], ['/search', pqsearchServer]]) {
      if (path === prefix || path.startsWith(prefix + '/')) { const sub = path.slice(prefix.length) || '/'; return mod.handleRequest(method, sub, body); }
    }
    if (method === 'GET' && (path === '/' || path === '/index.html')) return { status: 200, contentType: 'text/html; charset=utf-8', body: DASH };
    if (method === 'GET' && path === '/api/products') return json({ products: PRODUCTS });
    if (method === 'POST' && path === '/api/shield/grade') return json(shieldGrade(parse()));
    if (method === 'POST' && path === '/api/vc/issue') return json(vcIssue(parse()));
    if (method === 'POST' && path === '/api/sign') return json(codeSign(parse()));
    if (method === 'POST' && path === '/api/firmware/sign') return json(firmwareSign(parse()));
    if (method === 'POST' && path === '/api/consent/grant') return json(consentGrant(parse()));
    if (method === 'POST' && path === '/api/cap/issue') return json(capIssue(parse()));
    return json({ error: 'not found', products: PRODUCTS.map((p) => p.demo) }, 404);
  } catch (e) { return json({ error: String(e && e.message || e) }, 400); }
}

export async function serve(port = 8080) {
  const http = await import('node:http');
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; if (b.length > 5_000_000) req.destroy(); }); req.on('end', () => { const r = handleRequest(req.method, req.url.split('?')[0], b); res.statusCode = r.status; res.setHeader('content-type', r.contentType); res.end(r.body); }); });
  srv.listen(port, () => console.log(`trelyan-console (DEMO) on http://localhost:${port} — reference/DRAFT, no auth, do not expose`));
  return srv;
}

const DASH = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TRELYAN — product console (demo)</title><style>
:root{--bg:#05070c;--panel:#0b1220;--line:#16233b;--cyan:#39d0ff;--green:#39e08a;--dim:#8aa0bf;--txt:#e6eefb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 ui-sans-serif,system-ui,Segoe UI}
.wrap{max-width:960px;margin:0 auto;padding:26px 18px 60px}h1{font:600 22px/1.2 ui-sans-serif;margin:0 0 2px}
.sub{color:var(--dim);margin:0 0 20px}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}.card h3{margin:0 0 4px;font:600 15px ui-sans-serif;color:var(--cyan)}
.card .w{color:var(--dim);font-size:12px;min-height:32px}button{margin-top:8px;background:#10233b;color:var(--txt);border:1px solid #24507a;border-radius:8px;padding:7px 12px;font:600 13px ui-sans-serif;cursor:pointer}
button:hover{background:#16304f}a.btn{display:inline-block;margin-top:8px;text-decoration:none}.out{margin-top:8px;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--dim);word-break:break-word}
.ok{color:var(--green)}.note{color:var(--dim);font-size:12px;margin-top:18px}
</style></head><body><div class="wrap">
<h1>TRELYAN — product console <span class="mono" style="color:var(--dim);font-size:13px">(demo)</span></h1>
<p class="sub">One surface for the portfolio. Each card runs a REAL sign→verify roundtrip with the tested post-quantum core (Ed25519 ∧ ML-DSA-87). The richer products (OMEGA, messenger, search) are mounted as their own dashboards.</p>
<div class="grid" id="grid"></div>
<p class="note">Reference/DRAFT over audited @noble crypto. Demos use 2-family signers for speed; production uses the 3-family pqseal AND-composition. No auth/persistence — a demo console, not production hosting.</p>
</div><script>
const DEMOS={
 '/api/shield/grade':{body:{kex:'X25519MLKEM768',auth:'ML-DSA-87',tls:'TLSv1.3'},show:r=>'grade '+r.grade+' <span class=ok>✓</span>'},
 '/api/vc/issue':{body:{claims:{over18:true,country:'US'}},show:r=>'credential issued + verified '+(r.verified?'<span class=ok>✓</span>':'✗')},
 '/api/sign':{body:{artifact:'release-binary-v1.2.3'},show:r=>'artifact signed + verified '+(r.verified?'<span class=ok>✓</span>':'✗')},
 '/api/firmware/sign':{body:{deviceModel:'TRLN-Sensor-A',version:7},show:r=>'firmware v'+r.version+' verified '+(r.verified?'<span class=ok>✓</span>':'✗')+' · anti-rollback '+(r.anti_rollback_ok?'<span class=ok>✓</span>':'✗')},
 '/api/consent/grant':{body:{purposes:['ai_coaching'],categories:['HEART_RATE']},show:r=>'consent verified '+(r.granted_verified?'<span class=ok>✓</span>':'✗')+' · deny-by-default '+(r.deny_by_default_ok?'<span class=ok>✓</span>':'✗')},
 '/api/cap/issue':{body:{tool:'DatabaseQuery'},show:r=>'in-bounds '+(r.in_bounds_verified?'<span class=ok>✓</span>':'✗')+' · out-of-bounds rejected '+(r.out_of_bounds_rejected?'<span class=ok>✓</span>':'✗')},
};
async function load(){const {products}=await (await fetch('/api/products')).json();const g=document.getElementById('grid');
 g.innerHTML=products.map((p,i)=>'<div class="card"><h3>'+p.name+'</h3><div class="w">'+p.what+'</div>'+
   (DEMOS[p.demo]?'<button onclick="run('+i+',\\''+p.demo+'\\')">Run demo</button><div class="out" id="o'+i+'"></div>':'<a class="btn" href="'+p.demo+'"><button>Open ▸</button></a>')+'</div>').join('');}
async function run(i,ep){const d=DEMOS[ep];const o=document.getElementById('o'+i);o.textContent='running…';
 const r=await (await fetch(ep,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(d.body)})).json();o.innerHTML=d.show(r);}
load();
</script></body></html>`;

/* ---------------------------------------- self-test: node trelyan-console.mjs ---------------------------------------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const j = (r) => JSON.parse(r.body);

  ok(handleRequest('GET', '/', '').status === 200, 'dashboard served');
  ok(j(handleRequest('GET', '/api/products', '')).products.length === 9, 'products listed');

  // each real demo signs + verifies with the tested core
  ok(j(handleRequest('POST', '/api/shield/grade', JSON.stringify({ kex: 'X25519MLKEM768', auth: 'ML-DSA-87', tls: 'TLSv1.3' }))).grade === 'A', 'shield: full-PQ posture → grade A');
  ok(j(handleRequest('POST', '/api/shield/grade', JSON.stringify({ kex: 'X25519', auth: 'RSA', tls: 'TLSv1.3' }))).grade === 'D', 'shield: classical posture → grade D'); // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
  ok(j(handleRequest('POST', '/api/vc/issue', '{}')).verified === true, 'quantumdna: VC issued + verified');
  ok(j(handleRequest('POST', '/api/sign', '{}')).verified === true, 'code-signing: artifact signed + verified');
  const fw = j(handleRequest('POST', '/api/firmware/sign', '{}'));
  ok(fw.verified === true && fw.anti_rollback_ok === true, 'firmware: verified + anti-rollback enforced');
  const cs = j(handleRequest('POST', '/api/consent/grant', '{}'));
  ok(cs.granted_verified === true && cs.deny_by_default_ok === true, 'consent: verified + deny-by-default');
  const cap = j(handleRequest('POST', '/api/cap/issue', '{}'));
  ok(cap.in_bounds_verified === true && cap.out_of_bounds_rejected === true, 'capability: in-bounds verified + out-of-bounds rejected');

  // mounted services reachable through the console prefixes
  ok(j(handleRequest('GET', '/omega/api/manifest', '')).layers.length === 7, 'mounted /omega/api/manifest works');
  ok(handleRequest('POST', '/mesh/api/reset', '{}').status === 200, 'mounted /mesh reachable');
  const sr = handleRequest('GET', '/search/', '');
  ok(sr.status === 200 && /text\/html/.test(sr.contentType), 'mounted /search dashboard reachable (html)');
  ok(handleRequest('GET', '/nope', '').status === 404, 'unknown route → 404');

  console.log(`\ntrelyan-console self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--serve')) { const p = parseInt(process.argv[process.argv.indexOf('--serve') + 1], 10) || 8080; serve(p); }
  else selfTest();
}
