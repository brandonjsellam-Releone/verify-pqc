/*!
 * pqmesh-server — QuantumMesh messaging service (reference, DRAFT). Turns the SHIPPED messaging cores (pqx3dh PQXDH
 * handshake → pqratchet PQ triple ratchet, via omega-nexus) into a runnable ASYNC messenger: identities register +
 * publish a prekey bundle, a sender opens a session against a recipient's bundle, and exchanges MULTIPLE messages through
 * a store-and-forward MAILBOX. The relay stores + routes only CIPHERTEXT (end-to-end; it never holds plaintext or keys in
 * a real deployment) — framework-free node:http, testable without sockets via handleRequest, plus an embedded dashboard.
 *
 * HONEST SCOPE (what this is NOT):
 *  - DEMO: to show both endpoints on one page, THIS process holds both identities' ratchet state and decrypts server-side
 *    for the inbox view. In production the ratchet runs on each CLIENT DEVICE and the relay sees only ciphertext + routing
 *    metadata. The dashboard says so; do not read the demo's server-side decrypt as "the relay can read messages".
 *  - 1:1 async messaging only. NO group messaging (no MLS), NO multi-device sync, NO voice/video, NO onion/metadata
 *    anonymity, NO push, NO account/spam/abuse system, NO persistence (in-memory). Those are the "app" layer, not built.
 *  - No "unbreakable/quantum-safe/impossible" claims: forward secrecy + post-compromise security hold under HNDL +
 *    endpoint integrity; endpoint compromise breaks confidentiality. Peer identity must be PINNED out-of-band for TRUST.
 * Run: node pqmesh-server.mjs --serve 8788   |   Self-test: node pqmesh-server.mjs
 */
import { omegaIdentity, establishSession, send as ratchetSend, receive as ratchetReceive } from './omega-nexus.mjs';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

// deterministic per-id identity seed (demo; real identities are device-generated + pinned via pqkt)
const idSeed = (id) => sha256(utf8ToBytes('pqmesh-demo-identity:' + id)).slice(0, 32);
const convKey = (a, b) => [a, b].sort().join('\x1f');

function newState() {
  return { identities: new Map(), conversations: new Map(), mailboxes: new Map() };
}
const S = newState();

function register(id) {
  if (!id || typeof id !== 'string') throw new Error('register: id (string) required');
  if (!S.identities.has(id)) { S.identities.set(id, omegaIdentity(idSeed(id))); S.mailboxes.set(id, []); }
  return { id, registered: true };
}
function ensureConversation(from, to) {
  const k = convKey(from, to);
  if (S.conversations.has(k)) return S.conversations.get(k);
  if (!S.identities.has(from) || !S.identities.has(to)) throw new Error('both parties must register first');
  // initiator = `from`; pin the responder's identity out-of-band (both are local here → the pin is the responder's own key)
  const sess = establishSession(S.identities.get(from), S.identities.get(to), { trustedIkSigPub: S.identities.get(to).sig.publicKey });
  if (!sess.ok) throw new Error('session establishment failed: ' + sess.reason);
  // the double ratchet is symmetric after seeding: the initiator's state sends first; both states can send+receive.
  const conv = { stateOf: { [from]: sess.aliceState, [to]: sess.bobState }, parties: [from, to], n: 0 };
  S.conversations.set(k, conv);
  return conv;
}
// Advance `id`'s receive state over any not-yet-applied inbound, caching the plaintext. This mirrors a real client: a
// responder can only build a ratchet reply AFTER processing the initiator's received message (the double ratchet has no
// sending chain until then), so `sendMessage` calls this before encrypting. Idempotent (applied entries are skipped).
function applyInbound(id) {
  for (const m of S.mailboxes.get(id)) {
    if (m.applied) continue;
    const conv = S.conversations.get(convKey(m.from, id));
    if (!conv) { m.applied = true; m.decrypted_ok = false; m.text = null; continue; }
    const r = ratchetReceive(conv.stateOf[id], m.ciphertext);   // advances id's receive state (+ seeds a reply chain)
    m.applied = true; m.decrypted_ok = r.ok; m.text = r.ok ? r.text : null;
  }
}
function sendMessage(from, to, text) {
  register(from); register(to);
  const conv = ensureConversation(from, to);
  applyInbound(from);                                          // bring the sender's ratchet current (enables a responder's first reply)
  const ciphertext = ratchetSend(conv.stateOf[from], String(text));   // opaque ratchet message (E2E)
  const wire = JSON.stringify(ciphertext);
  S.mailboxes.get(to).push({ from, ciphertext, bytes: wire.length, seq: conv.n++, applied: false, decrypted_ok: false, text: null });
  return { delivered: true, to, ciphertext_bytes: wire.length };  // the relay only ever handled this opaque blob
}
function readInbox(id, opts = {}) {
  register(id);
  if (!opts.ciphertextOnly) applyInbound(id);                  // decrypt (advance receive state) unless this is the relay's ciphertext-only view
  const out = S.mailboxes.get(id).map((m) => ({ from: m.from, seq: m.seq, ciphertext_bytes: m.bytes,
    ...(opts.ciphertextOnly ? {} : { decrypted_ok: m.decrypted_ok, text: m.text }) }));
  S.mailboxes.set(id, []);   // deliver-once (drain)
  return out;
}

/** handleRequest(method, path, body) — pure handler; returns { status, contentType, body }. */
export function handleRequest(method, path, body) {
  const json = (o, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(o) });
  const parse = () => (typeof body === 'string' ? JSON.parse(body || '{}') : (body || {}));
  try {
    if (method === 'GET' && (path === '/' || path === '/index.html')) return { status: 200, contentType: 'text/html; charset=utf-8', body: DASH };
    if (method === 'POST' && path === '/api/register') { const { id } = parse(); return json(register(id)); }
    if (method === 'POST' && path === '/api/send') { const { from, to, text } = parse(); return json(sendMessage(from, to, text)); }
    if (method === 'GET' && path.startsWith('/api/inbox/')) return json({ id: decodeURIComponent(path.slice('/api/inbox/'.length)), messages: readInbox(decodeURIComponent(path.slice('/api/inbox/'.length))) });
    if (method === 'GET' && path.startsWith('/api/relay-view/')) return json({ note: 'exactly what the relay sees — ciphertext + routing only, no plaintext', messages: readInbox(decodeURIComponent(path.slice('/api/relay-view/'.length)), { ciphertextOnly: true }) });
    if (method === 'POST' && path === '/api/reset') { Object.assign(S, newState()); return json({ reset: true }); }
    return json({ error: 'not found', routes: ['POST /api/register', 'POST /api/send', 'GET /api/inbox/:id', 'GET /api/relay-view/:id', 'POST /api/reset'] }, 404);
  } catch (e) { return json({ error: String(e && e.message || e) }, 400); }
}

export async function serve(port = 8788) {
  const http = await import('node:http');
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; if (b.length > 2_000_000) req.destroy(); }); req.on('end', () => { const r = handleRequest(req.method, req.url.split('?')[0], b); res.statusCode = r.status; res.setHeader('content-type', r.contentType); res.end(r.body); }); });
  srv.listen(port, () => console.log(`pqmesh-server (QuantumMesh DEMO) on http://localhost:${port} — reference/DRAFT, no auth, do not expose`));
  return srv;
}

const DASH = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuantumMesh — PQ messenger (demo)</title><style>
:root{--bg:#06080d;--panel:#0c1424;--line:#182a44;--cyan:#4bd6ff;--green:#46e39a;--dim:#8aa0bf;--txt:#e7eefb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 ui-sans-serif,system-ui,Segoe UI}
.wrap{max-width:900px;margin:0 auto;padding:24px 18px 60px}h1{font:600 21px/1.2 ui-sans-serif;margin:0 0 2px}
.sub{color:var(--dim);margin:0 0 18px}.mono{font-family:ui-monospace,Menlo,monospace}.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}h2{font:600 12px/1 ui-sans-serif;text-transform:uppercase;letter-spacing:.1em;color:var(--cyan);margin:0 0 10px}
input,button{font:14px ui-sans-serif;border-radius:8px;border:1px solid #24507a;background:#10233b;color:var(--txt);padding:8px 10px}
button{cursor:pointer;font-weight:600}button:hover{background:#16304f}.msg{padding:6px 9px;border-radius:8px;background:#0e1a2c;margin:4px 0;border:1px solid var(--line)}
.me{border-color:#1c5a44}.ok{color:var(--green)}.note{color:var(--dim);font-size:12px;margin-top:8px}.ct{color:var(--dim);font-size:11px}
</style></head><body><div class="wrap">
<h1>QuantumMesh — post-quantum messenger <span class="mono" style="color:var(--dim);font-size:13px">(demo)</span></h1>
<p class="sub">PQXDH handshake (X25519 + ML-KEM-1024) → PQ triple ratchet. The relay stores/routes only ciphertext. Type as Alice or Bob; each message is ratchet-encrypted, delivered to the other's mailbox, and decrypted on receive.</p>
<div class="cols">
<div class="panel"><h2>Alice</h2><div id="a-log"></div><div style="display:flex;gap:6px;margin-top:8px"><input id="a-in" placeholder="message to Bob" style="flex:1"><button onclick="sendMsg('alice','bob')">Send</button></div><button onclick="poll('alice')" style="margin-top:6px">Check inbox</button></div>
<div class="panel"><h2>Bob</h2><div id="b-log"></div><div style="display:flex;gap:6px;margin-top:8px"><input id="b-in" placeholder="message to Alice" style="flex:1"><button onclick="sendMsg('bob','alice')">Send</button></div><button onclick="poll('bob')" style="margin-top:6px">Check inbox</button></div>
</div>
<div class="panel" style="margin-top:14px"><h2>What the relay sees</h2><div id="relay" class="ct">— send a message, then look here —</div>
<p class="note">The relay only ever holds the opaque ciphertext blob + routing (from/to). In production the ratchet runs on each device; here both run in-process so the page can show both sides. No "unbreakable" claims — endpoint compromise breaks confidentiality.</p></div>
<p class="note">Reference/DRAFT over the audited @noble crypto. 1:1 only — no group / multi-device / voice / metadata anonymity / persistence.</p>
</div><script>
const j=async(m,u,b)=>(await fetch(u,b?{method:m,headers:{'content-type':'application/json'},body:JSON.stringify(b)}:{method:m})).json();
async function reg(){await j('POST','/api/register',{id:'alice'});await j('POST','/api/register',{id:'bob'});}
function line(who,from,text,me){const d=document.getElementById(who+'-log');const e=document.createElement('div');e.className='msg'+(me?' me':'');e.innerHTML='<b>'+from+':</b> '+text;d.appendChild(e);}
async function sendMsg(from,to){const inp=document.getElementById(from[0]+'-in');const t=inp.value.trim();if(!t)return;inp.value='';
  const r=await j('POST','/api/send',{from,to,text:t});line(from[0],from,t,true);
  document.getElementById('relay').innerHTML='relay handled: <span class="mono">{ from:"'+from+'", to:"'+to+'", ciphertext:'+r.ciphertext_bytes+' bytes }</span> — plaintext never seen';
  poll(to);}
async function poll(who){const r=await j('GET','/api/inbox/'+who);for(const m of r.messages){line(who[0],m.from,(m.decrypted_ok?m.text:'[decrypt failed]'),false);}}
reg();
</script></body></html>`;

/* ---------------------------------------- self-test: node pqmesh-server.mjs ---------------------------------------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const j = (r) => JSON.parse(r.body);
  handleRequest('POST', '/api/reset', '{}');

  ok(j(handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }))).registered, 'register alice');
  ok(j(handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }))).registered, 'register bob');

  // Alice → Bob, two messages; Bob's inbox decrypts them in order
  const s1 = j(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'hello bob' })));
  ok(s1.delivered && s1.ciphertext_bytes > 0, 'send a→b #1 delivered as ciphertext');
  handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'second message' }));
  const inbox = j(handleRequest('GET', '/api/inbox/bob', '')).messages;
  ok(inbox.length === 2 && inbox[0].decrypted_ok && inbox[0].text === 'hello bob' && inbox[1].text === 'second message', 'bob inbox decrypts both in order');

  // Bob → Alice reply on the same conversation
  handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'hi alice' }));
  const ia = j(handleRequest('GET', '/api/inbox/alice', '')).messages;
  ok(ia.length === 1 && ia[0].text === 'hi alice' && ia[0].from === 'bob', 'alice receives bob reply');

  // relay-view exposes ONLY ciphertext (no plaintext leaks through the relay endpoint)
  handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'secret' }));
  const rv = j(handleRequest('GET', '/api/relay-view/bob', ''));
  ok(rv.messages.length === 1 && rv.messages[0].text === undefined && rv.messages[0].ciphertext_bytes > 0, 'relay-view shows ciphertext only, no plaintext');

  // interleaved (the real defect the review caught): initiator sends 2, responder replies BEFORE draining → must work
  handleRequest('POST', '/api/reset', '{}');
  handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
  handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));
  handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'x1' }));
  handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'x2' }));
  ok(j(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'y1' }))).delivered, 'interleaved: responder replies before draining (state advanced on send)');
  const bi = j(handleRequest('GET', '/api/inbox/bob', '')).messages;
  ok(bi.length === 2 && bi[0].text === 'x1' && bi[1].text === 'x2' && bi.every((m) => m.decrypted_ok), 'interleaved: bob still receives both inbound');
  const ai = j(handleRequest('GET', '/api/inbox/alice', '')).messages;
  ok(ai.length === 1 && ai[0].text === 'y1' && ai[0].decrypted_ok, 'interleaved: alice receives the reply');

  // dashboard + unknown route
  ok(handleRequest('GET', '/', '').status === 200, 'dashboard served');
  ok(handleRequest('GET', '/nope', '').status === 404, 'unknown route → 404');
  // errors fail-closed
  ok(handleRequest('POST', '/api/send', JSON.stringify({ from: 'ghost' })).status === 400, 'malformed send → 400');

  console.log(`\npqmesh-server self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--serve')) { const p = parseInt(process.argv[process.argv.indexOf('--serve') + 1], 10) || 8788; serve(p); }
  else selfTest();
}
