/*!
 * omega-server — TRELYAN OMEGA demo API + verification dashboard (reference, DRAFT). A framework-free node:http adapter
 * (like pqcbom-server) that serves the honest capability manifest, the product's self-signed capability attestation, and
 * a LIVE evidence-pack verification — all computed SERVER-SIDE with the audited @noble crypto (the browser only displays).
 * The embedded dashboard is the "show, don't tell" surface for a technical due-diligence session: the reviewer sees the
 * capability matrix (from the signed statement) + can verify a fresh Evidence Pack pass/fail per component, in real time.
 *
 * HONEST: reference/DRAFT, unaudited COMPOSITION over the audited @noble crypto; nothing is broadcast on-chain; no auth,
 * no persistence — a demo, not production hosting (put it behind a real gateway + authn before any exposure). The
 * verification is genuine (server runs the real verifiers); the dashboard makes no claim the browser did the crypto.
 * Routes: GET / (dashboard) · GET /api/manifest · GET /api/capability · GET /api/demo-evidence · POST /api/verify-evidence
 * Run: node omega-server.mjs --serve [port]   |   Self-test: node omega-server.mjs
 */
import { capabilityStatement, capabilityMatrix, gatedFeatures, claimHazards, attestCapabilities, verifyCapabilities, OMEGA_VERSION } from './omega.mjs';
import { buildEvidencePack, verifyEvidencePack } from './omega-evidence.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// deterministic DEMO identity + board (fixed seeds → reproducible; NOT production keys)
const seed = (n, l = 32) => new Uint8Array(l).fill(n);
function demoIssuer() {
  return { ed: (() => { const sk = seed(201); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })(), mldsa: ml_dsa87.keygen(seed(202)), slh: slh_dsa_sha2_256f.keygen(seed(203, 96)) };
}
function demoBoard() {
  return ['alice', 'bob', 'carol', 'dave', 'erin'].map((id, i) => ({ id, ed: (() => { const sk = seed(10 + i); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })(), mldsa: ml_dsa87.keygen(seed(20 + i)) }));
}
const pins3 = (s) => ({ 'ML-DSA-87': s.mldsa.publicKey, 'SLH-DSA-256f': s.slh.publicKey, 'Ed25519': s.ed.publicKey });
const signers3 = (s) => [
  { alg: 'ML-DSA-87', secretKey: s.mldsa.secretKey, publicKey: s.mldsa.publicKey },
  { alg: 'SLH-DSA-256f', secretKey: s.slh.secretKey, publicKey: s.slh.publicKey },
  { alg: 'Ed25519', secretKey: s.ed.secretKey, publicKey: s.ed.publicKey },
];

// cache the (slow-to-sign) demo artifacts so repeat requests are snappy
let _cache = null;
function demoArtifacts() {
  if (_cache) return _cache;
  const issuer = demoIssuer();
  const capability = attestCapabilities(signers3(issuer));
  const bundle = buildEvidencePack({ issuer, boardMembers: demoBoard(), artifact: new TextEncoder().encode('TRELYAN OMEGA demo evidence artifact'), ts: 1_700_000_000 });
  _cache = { issuer, issuerPinsHex: { 'ML-DSA-87': bytesToHex(issuer.mldsa.publicKey), 'SLH-DSA-256f': bytesToHex(issuer.slh.publicKey), 'Ed25519': bytesToHex(issuer.ed.publicKey) }, capability, bundle };
  return _cache;
}

/** handleRequest(method, path, body) — pure handler (no sockets); returns { status, contentType, body }. */
export function handleRequest(method, path, body) {
  const json = (obj, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(obj) });
  try {
    if (method === 'GET' && (path === '/' || path === '/index.html')) return { status: 200, contentType: 'text/html; charset=utf-8', body: DASHBOARD_HTML };
    if (method === 'GET' && path === '/api/manifest') return json({ omega_version: OMEGA_VERSION, layers: capabilityMatrix(), gates: gatedFeatures(), hazards: claimHazards() });
    if (method === 'GET' && path === '/api/capability') {
      const d = demoArtifacts();
      const v = verifyCapabilities(d.capability, { trusted: pins3(d.issuer), requireKinds: ['lattice', 'hash-based', 'classical'] });
      return json({ statement: d.capability.statement, suite: d.capability.seal.suite, issuer_pins: d.issuerPinsHex, self_verified: v.verified });
    }
    if (method === 'GET' && path === '/api/demo-evidence') {
      const d = demoArtifacts();
      const verdict = verifyEvidencePack(d.bundle, { issuerPins: pins3(d.issuer) });
      return json({ pack_summary: { v: d.bundle.pack.v, pack_sha512: d.bundle.pack.pack_sha512 }, issuer_pins: d.issuerPinsHex, verdict });
    }
    if (method === 'POST' && path === '/api/verify-evidence') {
      const req = typeof body === 'string' ? JSON.parse(body || '{}') : (body || {});
      if (!req.bundle) return json({ error: 'POST { bundle, issuerPins:{ "ML-DSA-87":hex, "SLH-DSA-256f":hex, "Ed25519":hex } }' }, 400);
      const issuerPins = {};
      for (const k of ['ML-DSA-87', 'SLH-DSA-256f', 'Ed25519']) if (req.issuerPins && req.issuerPins[k]) issuerPins[k] = hexToBytes(req.issuerPins[k]);
      return json({ verdict: verifyEvidencePack(req.bundle, { issuerPins }) });
    }
    return json({ error: 'not found', routes: ['/', '/api/manifest', '/api/capability', '/api/demo-evidence', 'POST /api/verify-evidence'] }, 404);
  } catch (e) { return json({ error: String(e && e.message || e) }, 400); }
}

/** serve(port) — node:http demo server. */
export async function serve(port = 8787) {
  const http = await import('node:http');
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 5_000_000) req.destroy(); });
    req.on('end', () => {
      const path = req.url.split('?')[0];
      const r = handleRequest(req.method, path, body);
      res.statusCode = r.status; res.setHeader('content-type', r.contentType); res.end(r.body);
    });
  });
  srv.listen(port, () => console.log(`omega-server (DEMO) on http://localhost:${port}  — reference/DRAFT, no auth, do not expose`));
  return srv;
}

const DASHBOARD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TRELYAN OMEGA — Capability & Verification Console</title><style>
:root{--bg:#05070c;--panel:#0b1220;--line:#16233b;--cyan:#39d0ff;--green:#39e08a;--amber:#ffb347;--red:#ff5470;--dim:#8aa0bf;--txt:#e6eefb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px 60px}h1{font:600 22px/1.2 ui-sans-serif;margin:0 0 2px;letter-spacing:.2px}
.sub{color:var(--dim);margin:0 0 22px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 18px;margin:0 0 18px}
h2{font:600 13px/1 ui-sans-serif;text-transform:uppercase;letter-spacing:.12em;color:var(--cyan);margin:0 0 12px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px}.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid}
.BUILT{color:var(--green);border-color:#1c6b46;background:#0c1f16}.REFERENCE{color:var(--cyan);border-color:#1c4a6b;background:#0c1a24}
.MOCK{color:var(--amber);border-color:#6b551c;background:#241f0c}.STUB{color:var(--dim);border-color:#33455f;background:#0e1626}.GATED{color:var(--red);border-color:#6b1c30;background:#240c14}
.ok{color:var(--green)}.bad{color:var(--red)}.pill{display:inline-block;padding:1px 7px;border-radius:6px;font-size:11px;margin:2px 4px 2px 0;border:1px solid var(--line);color:var(--dim)}
button{background:#10233b;color:var(--txt);border:1px solid #24507a;border-radius:8px;padding:8px 14px;font:600 13px ui-sans-serif;cursor:pointer}
button:hover{background:#16304f}.note{color:var(--dim);font-size:12px;margin-top:10px}.k{color:var(--cyan)}.small{font-size:12px;color:var(--dim)}
.grid2{display:grid;grid-template-columns:1fr;gap:0}#pins{word-break:break-all}
</style></head><body><div class="wrap">
<h1>TRELYAN <span class="k">OMEGA</span> — Capability &amp; Verification Console</h1>
<p class="sub">Post-quantum trust + provenance layer. Every status below is the product's own honest label, and the checks run server-side with the audited <span class="mono">@noble</span> crypto. <span class="mono" id="ver"></span></p>

<div class="panel"><h2>Capability matrix</h2><div style="overflow-x:auto"><table id="matrix"><thead><tr><th>Layer</th><th>Name</th><th>Status</th><th>Backing</th></tr></thead><tbody></tbody></table></div>
<p class="note">Legend: <span class="badge BUILT">BUILT</span> tested core &nbsp; <span class="badge REFERENCE">REFERENCE</span> built, productionization gated &nbsp; <span class="badge MOCK">MOCK</span> labelled placeholder &nbsp; <span class="badge GATED">GATED</span> deliberately not built.</p></div>

<div class="panel"><h2>Live evidence-pack verification</h2>
<p class="small">The server builds one PQ-signed Evidence Pack (a signed capability statement + a live 3-of-5 governance decision + a QIV inscription + a hybrid-key attestation) and verifies every component. This is the "verify it yourself" artifact.</p>
<button onclick="verify()">Build &amp; verify a fresh Evidence Pack</button>
<div id="verdict" style="margin-top:14px"></div></div>

<div class="panel"><h2>Self-signed capability attestation</h2>
<p class="small">The product signs its own capability claims (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519). If any layer status is edited, verification fails — no claim drift.</p>
<button onclick="cap()">Fetch &amp; verify the signed statement</button>
<div id="cap" style="margin-top:12px"></div></div>

<div class="panel"><h2>Machine-enforced gates</h2><div id="gates" class="small"></div></div>

<p class="note">Reference / DRAFT. Unaudited composition over the independently-audited <span class="mono">@noble/{post-quantum,curves}</span>. Nothing is broadcast on-chain. No auth/persistence — a demo surface, not production hosting. Falcon-1024 (FIPS 206) is DRAFT and only an optional on-chain leg.</p>
</div><script>
const badge=s=>'<span class="badge '+s+'">'+s+'</span>';
async function load(){const m=await (await fetch('/api/manifest')).json();document.getElementById('ver').textContent='OMEGA v'+m.omega_version;
const tb=document.querySelector('#matrix tbody');tb.innerHTML=m.layers.map(l=>'<tr><td class="mono">'+l.layer+'</td><td>'+l.name+'</td><td>'+badge(l.status)+'</td><td class="small mono">'+l.backing.join(', ')+'</td></tr>').join('');
document.getElementById('gates').innerHTML=m.gates.map(g=>'<span class="pill"><span class="mono">'+g.layer+'</span> '+g.feature+'</span>').join('');}
async function verify(){const el=document.getElementById('verdict');el.innerHTML='<span class="small">building + verifying…</span>';
const r=await (await fetch('/api/demo-evidence')).json();const v=r.verdict;const p=v.parts||{};
const row=(k,ok)=>'<div>'+(ok?'<span class="ok">✔</span>':'<span class="bad">�’</span>')+' '+k+'</div>';
el.innerHTML='<div style="font-weight:600;margin-bottom:6px">Overall: '+(v.verified?'<span class="ok">VERIFIED ✔</span>':'<span class="bad">FAILED</span>')+'</div>'
+row('capability statement (signed)',p.capability)+row('governance decision (3-of-5 executable)',p.governance)+row('QIV inscription (issuer-signed)',p.inscription)+row('hybrid-key attestation',p.keyAttestation)+row('top-level bundle seal',p.topSeal)+row('pack digest',p.digest)
+'<div class="small mono" style="margin-top:8px">pack_sha512: '+(r.pack_summary&&r.pack_summary.pack_sha512||'').slice(0,48)+'…</div>';}
async function cap(){const el=document.getElementById('cap');el.innerHTML='<span class="small">verifying…</span>';const r=await (await fetch('/api/capability')).json();
el.innerHTML='<div>'+(r.self_verified?'<span class="ok">✔ signed statement verifies</span>':'<span class="bad">✗ verify failed</span>')+' <span class="small mono">('+r.suite+')</span></div><div id="pins" class="small mono" style="margin-top:6px">issuer ML-DSA-87 pin: '+(r.issuer_pins&&r.issuer_pins["ML-DSA-87"]||"").slice(0,40)+'…</div>';}
load();
</script></body></html>`;

/* ---------------------------------------- self-test: node omega-server.mjs ---------------------------------------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const j = (r) => JSON.parse(r.body);
  const dash = handleRequest('GET', '/', '');
  ok(dash.status === 200 && /text\/html/.test(dash.contentType) && dash.body.includes('OMEGA'), 'GET / serves the dashboard HTML');
  const man = handleRequest('GET', '/api/manifest', '');
  ok(man.status === 200 && j(man).layers.length === 7 && j(man).gates.length >= 20, 'GET /api/manifest: 7 layers + gates');
  const cap = handleRequest('GET', '/api/capability', '');
  ok(cap.status === 200 && j(cap).self_verified === true && j(cap).statement.layers.length === 7, 'GET /api/capability: signed statement self-verifies');
  const ev = handleRequest('GET', '/api/demo-evidence', '');
  ok(ev.status === 200 && j(ev).verdict.verified === true, 'GET /api/demo-evidence: fresh pack verifies');
  // POST verify with the demo pack + its issuer pins → verifies
  const d = demoArtifacts();
  const post = handleRequest('POST', '/api/verify-evidence', JSON.stringify({ bundle: d.bundle, issuerPins: d.issuerPinsHex }));
  ok(post.status === 200 && j(post).verdict.verified === true, 'POST /api/verify-evidence: valid pack verifies');
  // POST with a tampered pack (flip a governance ballot) → fails
  const bad = JSON.parse(JSON.stringify(d.bundle)); bad.pack.governance.ballots[0].core.choice = 'reject';
  const post2 = handleRequest('POST', '/api/verify-evidence', JSON.stringify({ bundle: bad, issuerPins: d.issuerPinsHex }));
  ok(post2.status === 200 && j(post2).verdict.verified === false, 'POST /api/verify-evidence: tampered pack rejected');
  // wrong issuer pins → fails
  const post3 = handleRequest('POST', '/api/verify-evidence', JSON.stringify({ bundle: d.bundle, issuerPins: {} }));
  ok(j(post3).verdict.verified === false, 'POST /api/verify-evidence: missing issuer pins → not verified');
  // unknown route → 404
  ok(handleRequest('GET', '/nope', '').status === 404, 'unknown route → 404');

  console.log(`\nomega-server self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--serve')) { const p = parseInt(process.argv[process.argv.indexOf('--serve') + 1], 10) || 8787; serve(p); }
  else selfTest();
}
