var INDEXER="/api/pq/idx";
var THRONDAR="/api/pq/throndar";
var out=document.getElementById("out"), kind=document.getElementById("kind"), note=document.getElementById("note"), btn=document.getElementById("go"), q=document.getElementById("q");

function b64(b){var s=atob(b),u=new Uint8Array(s.length);for(var i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return u;}
function abi(b){if(b.length>=2){var d=(b[0]<<8)|b[1];if(d===b.length-2)return b.slice(2);}return b;}
function esc(s){return String(s).replace(/[<>&]/g,function(c){return{"<":"&lt;",">":"&gt;","&":"&amp;"}[c];});}

function detect(v){
  v=v.trim();
  if(/^\d+$/.test(v)) return "app";
  if(/^[A-Z2-7]{52}$/.test(v)) return "txid";
  if(/^[\{\[]/.test(v)) return "bundle";
  return "receipt";
}

async function appFromTxid(txid){
  var t=await fetch(INDEXER+"/v2/transactions/"+encodeURIComponent(txid)).then(function(r){return r.json();});
  var tx=t.transaction||{};
  var at=tx["application-transaction"]||{};
  return at["application-id"]||null;
}

async function verifyOnChain(app){
  var tr=await fetch(INDEXER+"/v2/transactions?application-id="+encodeURIComponent(app)+"&limit=100").then(function(r){return r.json();});
  var sig=null,txid=null,pub=false;
  (tr.transactions||[]).forEach(function(t){
    (((t["application-transaction"]||{})["application-args"])||[]).map(b64).map(abi).forEach(function(a){
      if(!sig&&a.length>600&&a.length<1500&&(a[0]&0x0f)===10){sig={header:"0x"+a[0].toString(16),len:a.length,det:!!(a[0]&0x80)};txid=t.id;}
      if(a.length===1793&&(a[0]&0x0f)===10)pub=true;
    });
  });
  var insc=false;try{var bx=await fetch(INDEXER+"/v2/applications/"+encodeURIComponent(app)+"/boxes?limit=100").then(function(r){return r.json();});insc=(bx.boxes||[]).some(function(x){var n=b64(x.name);return n.length>=2&&n[0]===0x69&&n[1]===0x5f;});}catch(e){}
  return {app:app,sig:sig,txid:txid,pub:pub,insc:insc,verified:!!(sig&&insc)};
}

async function verifyThrondar(input,isBundle){
  // Best-effort call to THRONDAR's public verify API. Shape-tolerant; falls back to deep-link.
  try{
    var res=await fetch(THRONDAR+"/api/v1/verify",{method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify(isBundle?JSON.parse(input):{receipt:input})});
    if(res.ok){ return {ok:true, data:await res.json()}; }
    return {ok:false, status:res.status};
  }catch(e){ return {ok:false, error:e.message}; }
}

function light(state,title,sub){
  var cls=state==="on"?"on":state==="warn"?"wn":state==="err"?"er":"pend";
  return '<div class="light '+cls+'"><div class="h"><span class="dot"></span>'+title+'</div><div class="s">'+esc(sub)+'</div></div>';
}

function renderOnChain(r){
  var pq = r.sig ? "on" : "warn";
  var anchor = r.verified ? "on" : (r.sig?"warn":"warn");
  out.innerHTML =
    '<div class="lights">'
    + light("warn","Provenance","on-chain mode — no AI receipt provided")
    + light(pq, "Post-quantum", r.sig? ("Falcon-1024 · header "+r.sig.header+" · "+r.sig.len+"B"):"no Falcon signature found")
    + light(anchor,"On-chain", r.verified?"write-once inscription present":(r.sig?"signature on chain, box unconfirmed":"none"))
    + '</div>'
    + (r.sig?('<div class="grid">'
      + '<div class="stat"><div class="k">Header</div><div class="v gold">'+r.sig.header+'</div></div>'
      + '<div class="stat"><div class="k">Size</div><div class="v">'+r.sig.len+' B</div></div>'
      + '<div class="stat"><div class="k">Mode</div><div class="v">'+(r.sig.det?"deterministic":"randomized")+'</div></div>'
      + '<div class="stat"><div class="k">Public key</div><div class="v '+(r.pub?"ok":"warn")+'">'+(r.pub?"1793 B":"not seen")+'</div></div>'
      + '</div>'):"")
    + '<div class="links">'
    + (r.txid?'<a target="_blank" rel="noopener" href="https://lora.algokit.io/testnet/transaction/'+esc(r.txid)+'">Signing txn ↗</a>':"")
    + '<a target="_blank" rel="noopener" href="https://lora.algokit.io/testnet/application/'+esc(r.app)+'">App '+esc(r.app)+' ↗</a></div>';
  note.innerHTML='<b class="gold">Reading.</b> Post-quantum = a Falcon-1024 signature is on chain. On-chain = the write-once <code>i_</code> box exists, which the contract writes only after <code>falcon_verify</code> passes. <code>0xBA</code> is trelyan-pq\'s deterministic-wrapper convention, not a NIST/FIPS field. TestNet, unaudited; reflects one indexer.';
}

function renderThrondar(input, t){
  var prov = t.ok ? "on":"warn";
  out.innerHTML =
    '<div class="lights">'
    + light(prov,"Provenance", t.ok?"THRONDAR verify responded":"could not reach verify API from browser")
    + light(t.ok?"on":"pend","Post-quantum","answers are signed ML-DSA-87 + Falcon-1024")
    + light("pend","On-chain","anchor lookup — see /anchor")
    + '</div>'
    + (t.ok?'<pre style="background:#0A0E1F;border:.5px solid var(--line);border-radius:10px;padding:14px;overflow:auto;font:400 12px/1.5 var(--mono);color:#cdd2e6">'+esc(JSON.stringify(t.data,null,2)).slice(0,1400)+'</pre>':"")
    + '<div class="links"><a target="_blank" rel="noopener" href="'+THRONDAR+'/verify">Open in THRONDAR verifier ↗</a></div>';
  note.innerHTML='<b class="gold">Reading.</b> Provenance is verified by THRONDAR\'s public API + transparency log; this page shows its verdict. Cross-browser CORS may block the call — use the deep-link. On-chain anchoring is shown once the two-layer anchor is live (see <code>/anchor</code>).';
}

async function run(){
  var v=q.value.trim(); if(!v){return;}
  var k=detect(v); kind.textContent="detected: "+k;
  btn.disabled=true; out.innerHTML='<p class="detail"><span class="spin"></span> Verifying…</p>'; note.textContent="";
  try{
    if(k==="app"){ renderOnChain(await verifyOnChain(v)); }
    else if(k==="txid"){ var app=await appFromTxid(v); if(!app){out.innerHTML='<p class="bad">No application id on that transaction.</p>';} else renderOnChain(await verifyOnChain(app)); }
    else { renderThrondar(v, await verifyThrondar(v, k==="bundle")); }
  }catch(e){ out.innerHTML='<p class="bad">Verify failed: '+esc(e.message||e)+'</p>'; }
  finally{ btn.disabled=false; }
}
btn.addEventListener("click",run);
q.addEventListener("keydown",function(e){if(e.key==="Enter")run();});
Array.prototype.forEach.call(document.querySelectorAll(".ex"),function(b){b.addEventListener("click",function(){q.value=b.getAttribute("data-q");run();});});
run();
