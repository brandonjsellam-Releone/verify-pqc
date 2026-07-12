/*!
 * pqsearch-server — QDS-Ω verifiable search engine service (reference, DRAFT). Turns the SHIPPED search core (pqindex:
 * a signed Merkle index over lexicographically-sorted terms with inclusion + absence proofs) into a runnable engine:
 * ingest documents → a signed shard; query a term → the matching documents PLUS a proof that the result is honest:
 *   • an INCLUSION proof — the returned postings are provably in the signed index (fabricating a result would require
 *     forging a signature over a different Merkle root);
 *   • an ABSENCE / non-omission proof — "no results" is provably true for THIS signed index (omitting/censoring a term
 *     would require a different signed root, i.e. a detectable, attributable act — the server is not structurally unable
 *     to censor; a censored answer is EVIDENT).
 * Framework-free node:http, testable without sockets via handleRequest, plus an embedded dashboard. This is the honest
 * differentiator of QDS-Ω: not "a better ranker", but a search engine whose results are TAMPER-EVIDENT + CENSORSHIP-EVIDENT
 * (evidence of dishonesty — NOT a structural guarantee that the server cannot censor).
 *
 * HONEST SCOPE (what this is NOT): NO crawler, NO ranking/relevance model, NO natural-language/semantic query, NO
 * distributed shard network, NO browser/Tor front-end, NO persistence (in-memory), NO spam/quality signals. Those are the
 * "engine at web scale" layer and are multi-year — not built. Anti-rollback (serving a stale-but-signed shard) needs an
 * external fresh checkpoint (same freshness obligation as pqkt), not provided here. Exact-term match only.
 * Run: node pqsearch-server.mjs --serve 8789   |   Self-test: node pqsearch-server.mjs
 */
import { buildSignedShard, verifyShard, termInclusionProof, verifyTermInclusion, absenceProof, verifyAbsenceInShard } from './pqindex.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const tokenize = (text) => Array.from(new Set(String(text).toLowerCase().match(/[a-z0-9]+/g) || []));
const idxSeed = sha256(utf8ToBytes('pqsearch-demo-index-key')).slice(0, 32);   // deterministic demo signer (NOT production)

function newState() {
  const kp = ml_dsa87.keygen(idxSeed);
  return { idxSecret: kp.secretKey, idxPublic: kp.publicKey, docs: new Map(), shard: null };
}
const S = newState();

function rebuildShard() {
  const inv = new Map();                       // term -> Set(docId)
  for (const [id, text] of S.docs) for (const t of tokenize(text)) { if (!inv.has(t)) inv.set(t, new Set()); inv.get(t).add(id); }
  const terms = [...inv.entries()].map(([term, ids]) => ({ term, postings: [...ids].sort() }));   // unique terms, sorted postings
  S.shard = terms.length ? buildSignedShard({ term_range: ['\x00', '￿'], terms, version: S.docs.size }, S.idxSecret, S.idxPublic, { ts: S.docs.size }) : null;
  return S.shard;
}

function ingest(docs) {
  if (!Array.isArray(docs)) throw new Error('ingest: { docs:[{id,text}] } required');
  for (const d of docs) { if (!d || !d.id || typeof d.text !== 'string') throw new Error('ingest: each doc needs {id, text}'); S.docs.set(String(d.id), d.text); }
  rebuildShard();
  return { ingested: docs.length, total_docs: S.docs.size, index_terms: S.shard ? S.shard.tree_size : 0, merkle_root: S.shard ? S.shard.merkle_root : null };
}

function query(termRaw) {
  const term = String(termRaw || '').toLowerCase().trim();
  if (!term) throw new Error('query: term required');
  // empty index: there is NO signed shard, hence NO absence proof (absence proofs need tree_size >= 1). Do not claim
  // provably_complete — an unproven "no results" must not render as verified (fail-closed).
  if (!S.shard) return { term, found: false, provably_complete: false, reason: 'empty index — no signed shard, no proof', hits: [], proof_kind: null };
  const incl = termInclusionProof(S.shard, term);
  if (incl) {
    // present: return the docs + an inclusion proof; provably_complete = the proof verifies against the signed root
    const ok = verifyTermInclusion(S.shard.merkle_root, incl);
    const hits = incl.postings.map((id) => ({ id, snippet: (S.docs.get(id) || '').slice(0, 120) }));
    return { term, found: true, hits, provably_complete: ok, proof_kind: 'inclusion', merkle_root: S.shard.merkle_root, proof: incl };
  }
  // absent: prove non-omission (the term is genuinely not in THIS signed index — a censored answer would be evident)
  const abs = absenceProof(S.shard, term);
  const ok = !!abs && verifyAbsenceInShard(S.shard, abs, S.idxPublic);
  return { term, found: false, hits: [], provably_complete: ok, proof_kind: 'absence', merkle_root: S.shard.merkle_root, proof: abs };
}

/** handleRequest(method, path, body) — pure handler; returns { status, contentType, body }. */
export function handleRequest(method, path, body) {
  const json = (o, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(o) });
  const parse = () => (typeof body === 'string' ? JSON.parse(body || '{}') : (body || {}));
  try {
    if (method === 'GET' && (path === '/' || path === '/index.html')) return { status: 200, contentType: 'text/html; charset=utf-8', body: DASH };
    if (method === 'POST' && path === '/api/ingest') return json(ingest(parse().docs));
    if (method === 'GET' && path === '/api/index') return json(S.shard ? { merkle_root: S.shard.merkle_root, tree_size: S.shard.tree_size, version: S.shard.version, signer_pub: S.shard.signer_pub, sig: S.shard.sig, self_verified: verifyShard(S.shard, S.idxPublic).verified } : { empty: true });
    if (method === 'POST' && path === '/api/query') return json(query(parse().term));
    if (method === 'POST' && path === '/api/reset') { Object.assign(S, newState()); return json({ reset: true }); }
    return json({ error: 'not found', routes: ['POST /api/ingest', 'GET /api/index', 'POST /api/query', 'POST /api/reset'] }, 404);
  } catch (e) { return json({ error: String(e && e.message || e) }, 400); }
}

export async function serve(port = 8789) {
  const http = await import('node:http');
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; if (b.length > 4_000_000) req.destroy(); }); req.on('end', () => { const r = handleRequest(req.method, req.url.split('?')[0], b); res.statusCode = r.status; res.setHeader('content-type', r.contentType); res.end(r.body); }); });
  srv.listen(port, () => console.log(`pqsearch-server (QDS-Ω DEMO) on http://localhost:${port} — reference/DRAFT, no auth, do not expose`));
  return srv;
}

const DASH = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QDS-Ω — verifiable search (demo)</title><style>
:root{--bg:#06080d;--panel:#0c1424;--line:#182a44;--cyan:#4bd6ff;--green:#46e39a;--amber:#ffc061;--dim:#8aa0bf;--txt:#e7eefb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.55 ui-sans-serif,system-ui,Segoe UI}
.wrap{max-width:820px;margin:0 auto;padding:26px 18px 60px}h1{font:600 21px/1.2 ui-sans-serif;margin:0 0 2px}
.sub{color:var(--dim);margin:0 0 18px}.mono{font-family:ui-monospace,Menlo,monospace}.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}
input,button{font:15px ui-sans-serif;border-radius:8px;border:1px solid #24507a;background:#10233b;color:var(--txt);padding:10px 12px}
button{cursor:pointer;font-weight:600}button:hover{background:#16304f}.hit{padding:8px 10px;border-radius:8px;background:#0e1a2c;margin:6px 0;border:1px solid var(--line)}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid}
.ok{color:var(--green);border-color:#1c6b46;background:#0c1f16}.amber{color:var(--amber);border-color:#6b551c;background:#241f0c}.dim{color:var(--dim)}.note{color:var(--dim);font-size:12px;margin-top:10px}
</style></head><body><div class="wrap">
<h1>QDS-Ω — verifiable search <span class="mono dim" style="font-size:13px">(demo)</span></h1>
<p class="sub">A search engine whose results are <b>tamper-evident + censorship-evident</b>: every answer ships a proof. A hit carries an <span class="ok badge">inclusion proof</span> (provably not fabricated in this index); "no results" carries an <span class="ok badge">absence proof</span> (provably not omitted in this index). Verified against a signed Merkle index (ML-DSA-87). This makes dishonesty <i>evident</i> — not structurally impossible.</p>
<div class="panel"><div style="display:flex;gap:8px"><input id="q" placeholder="search a term (e.g. lattice, falcon, signal)" style="flex:1" onkeydown="if(event.key==='Enter')go()"><button onclick="go()">Search</button></div>
<div id="out" style="margin-top:12px"></div></div>
<p class="note">Reference/DRAFT over audited @noble crypto. Exact-term match only — NO crawler, ranking, semantic query, shard network, or browser. That's the web-scale layer (not built). Anti-rollback (stale signed shard) needs an external fresh checkpoint.</p>
</div><script>
const SEED=[{id:"doc-kyber",text:"ML-KEM (Kyber) is the FIPS 203 lattice key encapsulation mechanism."},
{id:"doc-falcon",text:"Falcon is the FN-DSA lattice signature (FIPS 206, in development — not yet standardized); compact signatures."},
{id:"doc-signal",text:"Signal PQXDH uses lattice ML-KEM plus X25519 for post-quantum key agreement."},
{id:"doc-sphincs",text:"SLH-DSA (SPHINCS+) is the FIPS 205 stateless hash-based signature scheme."}];
async function j(m,u,b){return (await fetch(u,{method:m,headers:{'content-type':'application/json'},body:JSON.stringify(b)})).json();}
async function boot(){await j('POST','/api/reset',{});await j('POST','/api/ingest',{docs:SEED});}
async function go(){const term=document.getElementById('q').value.trim();if(!term)return;const r=await j('POST','/api/query',{term});
 const o=document.getElementById('out');let h='';
 if(r.found){h+='<div><span class="ok badge">✓ '+r.hits.length+' result(s) — inclusion proof '+(r.provably_complete?'verified':'FAILED')+'</span></div>';
   for(const x of r.hits)h+='<div class="hit"><b class="mono">'+x.id+'</b><br><span class="dim">'+x.snippet+'</span></div>';}
 else{h+='<div><span class="amber badge">no results — absence proof '+(r.provably_complete?'verified (censorship-evident)':'FAILED')+'</span></div>';}
 h+='<div class="note mono">root '+(r.merkle_root||'').slice(0,32)+'… · proof: '+r.proof_kind+'</div>';
 o.innerHTML=h;}
boot();
</script></body></html>`;

/* ---------------------------------------- self-test: node pqsearch-server.mjs ---------------------------------------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const j = (r) => JSON.parse(r.body);
  handleRequest('POST', '/api/reset', '{}');

  // sweep-R1 lock: an EMPTY index has NO signed shard → NO proof → provably_complete MUST be false (was fail-open true)
  { const e = j(handleRequest('POST', '/api/query', JSON.stringify({ term: 'anything' }))); ok(e.found === false && e.provably_complete === false && e.proof_kind === null, 'empty index: provably_complete FALSE (no shard, no proof — fail-closed)'); }

  const ing = j(handleRequest('POST', '/api/ingest', JSON.stringify({ docs: [
    { id: 'd1', text: 'lattice cryptography ML-KEM quantum' },
    { id: 'd2', text: 'falcon signature lattice compact' },
    { id: 'd3', text: 'signal messenger post quantum' },
  ] })));
  ok(ing.total_docs === 3 && ing.index_terms > 0 && ing.merkle_root, 'ingest: 3 docs → signed index');

  // signed index self-verifies
  const idx = j(handleRequest('GET', '/api/index', ''));
  ok(idx.self_verified === true && typeof idx.merkle_root === 'string', 'index: signed shard self-verifies');

  // present term → inclusion proof verifies + correct postings (lattice in d1 & d2)
  const ql = j(handleRequest('POST', '/api/query', JSON.stringify({ term: 'lattice' })));
  ok(ql.found && ql.provably_complete && ql.proof_kind === 'inclusion', 'query lattice: found + inclusion proof verified');
  ok(ql.hits.map((h) => h.id).sort().join(',') === 'd1,d2', 'query lattice: correct postings (d1,d2)');
  // independently verify the returned proof against the returned root (client-side check)
  ok(verifyTermInclusion(ql.merkle_root, ql.proof) === true, 'query lattice: proof verifies independently against root');

  // absent term → absence proof verifies (censorship-evident: a hidden result would need a different signed root)
  const qz = j(handleRequest('POST', '/api/query', JSON.stringify({ term: 'zzznotindexed' })));
  ok(!qz.found && qz.provably_complete && qz.proof_kind === 'absence', 'query missing term: absence proof verified (censorship-evident)');

  // single-term present
  const qf = j(handleRequest('POST', '/api/query', JSON.stringify({ term: 'falcon' })));
  ok(qf.found && qf.hits.length === 1 && qf.hits[0].id === 'd2', 'query falcon: single correct hit');

  // adding a doc changes the signed root (index is live)
  const beforeRoot = idx.merkle_root;
  handleRequest('POST', '/api/ingest', JSON.stringify({ docs: [{ id: 'd4', text: 'newterm added later' }] }));
  const idx2 = j(handleRequest('GET', '/api/index', ''));
  ok(idx2.merkle_root !== beforeRoot && idx2.self_verified, 'ingest more: root updates + still self-verifies');
  ok(j(handleRequest('POST', '/api/query', JSON.stringify({ term: 'newterm' }))).found, 'newly-ingested term is now findable');

  // errors fail-closed
  ok(handleRequest('POST', '/api/ingest', JSON.stringify({ docs: [{ id: 'x' }] })).status === 400, 'malformed ingest → 400');
  ok(handleRequest('GET', '/', '').status === 200, 'dashboard served');
  ok(handleRequest('GET', '/nope', '').status === 404, 'unknown route → 404');

  console.log(`\npqsearch-server self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--serve')) { const p = parseInt(process.argv[process.argv.indexOf('--serve') + 1], 10) || 8789; serve(p); }
  else selfTest();
}
