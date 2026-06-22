var THRONDAR="/api/pq/throndar", INDEXER="/api/pq/idx";
var RECOGNIZED_APPS=new Set(["763809096","764917520"]); // TRELYAN inscription contracts (app-ids unforgeable)
var INSCRIBE_SELECTOR="9d300cf2"; // inscribe(cell,commit,sig,uri) ABI method selector — commit is arg[2]
var DOMAIN="TRELYAN-ANCHOR-v1";
function enc(s){return new TextEncoder().encode(s);}
function u64be(n){var a=new Uint8Array(8),b=BigInt(n);for(var i=7;i>=0;i--){a[i]=Number(b&0xffn);b>>=8n;}return a;}
function hexb(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}
function cat(arr){var n=arr.reduce(function(s,a){return s+a.length;},0),o=new Uint8Array(n),k=0;arr.forEach(function(a){o.set(a,k);k+=a.length;});return o;}
function commitment(sth){var p=cat([enc(DOMAIN),new Uint8Array([0]),enc(sth.log),new Uint8Array([0]),u64be(sth.tree_size),hexb(sth.root_hash),u64be(sth.timestamp)]);return sha512_256(p);}
function esc(s){return String(s).replace(/[<>&]/g,function(c){return{"<":"&lt;",">":"&gt;","&":"&amp;"}[c];});}
function b64(b){var s=atob(b),u=new Uint8Array(s.length);for(var i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return u;}
function hex(u){var h="";for(var i=0;i<u.length;i++)h+=u[i].toString(16).padStart(2,"0");return h;}

async function main(){
  var data;
  try{ data=await fetch(THRONDAR+"/api/transparency/ledger").then(function(r){return r.json();}); }
  catch(e){ document.getElementById("sthPanel").innerHTML='<p class="warn">Could not reach THRONDAR ('+esc(e.message)+'). CORS may block cross-origin; the mechanism is unchanged.</p>'; return; }
  var s=data.signed_tree_head||{}, signed=s.signed, f=typeof signed==="string"?JSON.parse(signed):(signed||{});
  var sth={log:f.log||data.log,tree_size:+(f.tree_size!=null?f.tree_size:data.tree_size||0),root_hash:f.root_hash||data.root_hash,timestamp:+(f.timestamp||0)};
  var sig=(s.receipt||{}).sig;

  document.getElementById("sthPanel").innerHTML=
    '<div class="kv">'
    +'<div class="k">Log</div><div class="v gold">'+esc(sth.log)+'</div>'
    +'<div class="k">Algorithm</div><div class="v">'+esc(data.algo||"RFC6962-SHA256")+'</div>'
    +'<div class="k">Tree size</div><div class="v">'+sth.tree_size+'</div>'
    +'<div class="k">Root hash</div><div class="v">'+esc(sth.root_hash)+'</div>'
    +'<div class="k">Timestamp</div><div class="v">'+sth.timestamp+' <span class="mut">('+new Date(sth.timestamp*1000).toISOString()+')</span></div>'
    +'<div class="k">STH signature</div><div class="v '+(sig?"ok":"warn")+'">'+(sig?"ML-DSA-87 present ✓ ("+sig.length/2+" B)":"none")+'</div>'
    +'</div>';

  var commit=commitment(sth);
  document.getElementById("commitPanel").innerHTML=
    '<div class="kv">'
    +'<div class="k">Domain</div><div class="v">'+DOMAIN+'</div>'
    +'<div class="k">Commitment</div><div class="v gold">'+commit+'</div>'
    +'<div class="k">Hash</div><div class="v">sha512_256(domain ‖ log ‖ tree_size ‖ root ‖ timestamp)</div>'
    +'</div><p class="mut" style="margin:12px 0 0;font-size:13px">This 32-byte value is what an anchor inscription commits to. Recomputed live — it matches <code>anchor_sth.py prepare</code> for the same tree head.</p>';

  // optional anchors manifest (./anchors.json): [{ "txid": "...", "sth": {...} }]
  var manifest=[];
  try{ manifest=await fetch("./anchors.json").then(function(r){return r.ok?r.json():[];}); }catch(e){}
  var ap=document.getElementById("anchorsPanel");
  if(!manifest.length){
    ap.innerHTML='<p class="mut">No anchors inscribed yet. The first anchor is a gated owner step: run <code>anchor_sth.py prepare</code>, Falcon-sign the commitment, and <code>inscribe</code> it on app <code>763809096</code>. Anchors then appear here and verify against the chain automatically.</p>';
    return;
  }
  ap.innerHTML='<p class="mut"><span class="spin"></span> verifying '+manifest.length+' anchor(s) against the chain…</p>';
  var rows=[];
  for(var i=0;i<manifest.length;i++){
    var m=manifest[i], want=commitment(m.sth), ok=false, label="", reason="";
    try{ var t=await fetch(INDEXER+"/v2/transactions/"+m.txid).then(function(r){return r.json();});
      var at=(t.transaction||{})["application-transaction"]||{};
      var appId=String(at["application-id"]||"");
      var args=(at["application-args"]||[]).map(b64);
      var sel=args[0]?hex(args[0]):"";
      var commitArg=(args[2]&&args[2].length===32)?hex(args[2]):null; // inscribe(cell, commit, sig, uri) -> arg[2]
      if(!RECOGNIZED_APPS.has(appId)) reason="txn app "+appId+" is not a recognized TRELYAN contract";
      else if(sel!==INSCRIBE_SELECTOR) reason="txn is not an inscribe() call";
      else if(commitArg!==want) reason="on-chain commit does not match this tree head";
      else { ok=true; label="✓ inscribed · commit matches"; }
    }catch(e){ reason="lookup failed"; }
    if(!ok && !reason) reason="unconfirmed";
    rows.push('<div class="row" style="padding:10px 0;border-top:.5px solid var(--line)">'
      +'<div><div class="k mut" style="font:500 11px/1 var(--mono)">TREE SIZE '+esc(m.sth.tree_size)+' · '+esc(m.sth.timestamp)+(m.app_id?" · app "+esc(m.app_id):"")+'</div>'
      +'<div class="v" style="font:500 12px/1.5 var(--mono);word-break:break-all">'+esc(want)+'</div></div>'
      +'<div style="text-align:right"><span class="pill" style="color:'+(ok?"var(--ok)":"var(--warn)")+'">'+(ok?label:esc("unverified: "+reason))+'</span><div style="margin-top:8px"><a class="gold" target="_blank" rel="noopener" href="https://lora.algokit.io/testnet/transaction/'+esc(m.txid)+'">txn ↗</a></div></div></div>');
  }
  ap.innerHTML=rows.join("")+'<p class="mut" style="margin:14px 0 0;font-size:13px">A ✓ confirms <b>Layer 2</b> only: a <b>recognized</b> TRELYAN contract inscribed this exact tree-head commitment via a <code>falcon_verify</code>-gated <code>inscribe()</code> call (app-id, method selector, and commit arg all checked). It does <b>not</b> re-run the <b>Layer 1</b> ML-DSA-87 STH signature in your browser — that is shown above as THRONDAR\'s claim; cross-check it independently at <code>'+THRONDAR+'/api/transparency/ledger</code>.</p>';
}
main();
