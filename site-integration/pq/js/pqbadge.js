/*!
 * pqBadge — drop-in live "post-quantum verified on-chain" pill. MIT.
 * Usage:  <span data-pq-app="763809096"></span>  then  <script src="pqbadge.js"></script>
 * Options (data-attrs): data-pq-app, data-pq-indexer, data-pq-network (default testnet).
 * Honest by design: says "verified on-chain" only when a Falcon-1024 signature AND the
 * write-once inscription box are both present (the contract writes that box only after
 * falcon_verify passes). Trusts the single indexer it queries. TestNet, unaudited.
 */
(function () {
  'use strict';
  var DEF_INDEXER = '/api/pq/idx';

  function b64(b) { var s = atob(b), u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
  function abi(b) { if (b.length >= 2) { var d = (b[0] << 8) | b[1]; if (d === b.length - 2) return b.slice(2); } return b; }

  async function verify(app, indexer) {
    var tr = await fetch(indexer + '/v2/transactions?application-id=' + encodeURIComponent(app) + '&limit=100').then(function (r) { return r.json(); });
    var sig = null, txid = null;
    (tr.transactions || []).forEach(function (t) {
      (((t['application-transaction'] || {})['application-args']) || []).map(b64).map(abi).forEach(function (a) {
        if (!sig && a.length > 600 && a.length < 1500 && (a[0] & 0x0f) === 10) {
          sig = { header: '0x' + a[0].toString(16), len: a.length, det: !!(a[0] & 0x80) }; txid = t.id;
        }
      });
    });
    var insc = false;
    try {
      var bx = await fetch(indexer + '/v2/applications/' + encodeURIComponent(app) + '/boxes?limit=100').then(function (r) { return r.json(); });
      insc = (bx.boxes || []).some(function (x) { var n = b64(x.name); return n.length >= 2 && n[0] === 0x69 && n[1] === 0x5f; });
    } catch (e) { /* boxes optional */ }
    return { sig: sig, txid: txid, insc: insc, verified: !!(sig && insc) };
  }

  function css() {
    if (document.getElementById('pqb-css')) return;
    var s = document.createElement('style'); s.id = 'pqb-css';
    s.textContent = '.pqb{display:inline-flex;align-items:center;gap:6px;font:500 12px/1 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:5px 10px;border-radius:999px;border:1px solid;text-decoration:none;vertical-align:middle;cursor:pointer}.pqb-d{width:7px;height:7px;border-radius:50%;flex:none}.pqb-v{color:#0F6E56;border-color:rgba(15,110,86,.35);background:rgba(93,202,165,.12)}.pqb-v .pqb-d{background:#1D9E75}.pqb-w{color:#854F0B;border-color:rgba(133,79,11,.35);background:rgba(239,159,39,.12)}.pqb-w .pqb-d{background:#EF9F27}.pqb-e{color:#A32D2D;border-color:rgba(163,45,45,.35);background:rgba(226,75,74,.1)}.pqb-e .pqb-d{background:#E24B4A}.pqb-p .pqb-d{background:#9aa0b6;animation:pqbp 1s infinite}@keyframes pqbp{50%{opacity:.3}}';
    document.head.appendChild(s);
  }

  function pill(host) { var a = host.querySelector('a.pqb'); if (!a) { a = document.createElement('a'); host.appendChild(a); } return a; }
  function render(host, cls, label, title, href) {
    var a = pill(host); a.className = 'pqb ' + cls; a.setAttribute('role', 'status'); a.setAttribute('aria-live', 'polite');
    a.title = title; a.setAttribute('aria-label', title);
    a.innerHTML = '<span class="pqb-d" aria-hidden="true"></span><span></span>';
    a.lastChild.textContent = label;
    if (href) { a.href = href; a.target = '_blank'; a.rel = 'noopener'; } else { a.removeAttribute('href'); }
  }

  function mount(el) {
    var app = el.getAttribute('data-pq-app');
    var indexer = (el.getAttribute('data-pq-indexer') || DEF_INDEXER).replace(/\/$/, '');
    var net = el.getAttribute('data-pq-network') || 'testnet';
    css();
    render(el, 'pqb-p', 'verifying…', 'Checking the post-quantum signature on-chain…', null);
    if (!app) { render(el, 'pqb-w', 'no app id', 'Set data-pq-app to an Algorand application id.', null); return; }
    var base = 'https://lora.algokit.io/' + net;
    verify(app, indexer).then(function (r) {
      if (r.verified) render(el, 'pqb-v', 'post-quantum verified on-chain',
        'Falcon-1024 ' + (r.sig.det ? '(deterministic) ' : '') + r.sig.len + 'B, header ' + r.sig.header + '; write-once inscription present. ' + net + ', unaudited.',
        base + '/transaction/' + r.txid);
      else if (r.sig) render(el, 'pqb-w', 'PQ signature · unconfirmed',
        'A Falcon-1024 signature is on chain, but no write-once box confirmed acceptance.', base + '/application/' + app);
      else render(el, 'pqb-w', 'no PQ signature', 'No Falcon-1024 signature found for this app.', base + '/application/' + app);
    }).catch(function (e) { render(el, 'pqb-e', 'verify error', 'Indexer lookup failed: ' + (e.message || e), null); });
  }

  function init() { var els = document.querySelectorAll('[data-pq-app]'); for (var i = 0; i < els.length; i++) mount(els[i]); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
  window.pqBadge = { mount: mount, init: init };
})();
