const INDEXER = "/api/pq/idx";
const out = document.getElementById("out");
const note = document.getElementById("note");
const btn = document.getElementById("go");

function b64ToBytes(b64){ const s=atob(b64); const u=new Uint8Array(s.length); for(let i=0;i<s.length;i++)u[i]=s.charCodeAt(i); return u; }
function abiDecode(b){ if(b.length>=2){ const d=(b[0]<<8)|b[1]; if(d===b.length-2) return b.slice(2);} return b; }
function inspect(sig){ const h=sig[0]; return { hex:"0x"+h.toString(16).padStart(2,"0"), logn:h&0x0F, det:!!(h&0x80), compressed:(h&0x70)===0x30, len:sig.length }; }
function esc(s){ return String(s).replace(/[<>&]/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;"}[c])); }

async function verify(app){
  const tr = await fetch(`${INDEXER}/v2/transactions?application-id=${app}&limit=100`).then(r=>r.json());
  let sig=null, sigTxid=null, sigRound=null, pub=false, pubTxid=null;
  for(const t of (tr.transactions||[])){
    const args=(((t["application-transaction"]||{})["application-args"])||[]).map(b64ToBytes).map(abiDecode);
    for(const a of args){
      if(!sig && a.length>600 && a.length<1500 && (a[0]&0x0F)===10){ sig=inspect(a); sigTxid=t.id; sigRound=t["confirmed-round"]; }
      if(a.length===1793 && (a[0]&0x0F)===10){ pub=true; pubTxid=t.id; }
    }
  }
  let boxes=[];
  try{ const bx=await fetch(`${INDEXER}/v2/applications/${app}/boxes?limit=100`).then(r=>r.json()); boxes=(bx.boxes||[]).map(b=>b64ToBytes(b.name)); }catch(e){}
  const insc = boxes.some(n=>n.length>=2 && n[0]===0x69 && n[1]===0x5f); // "i_"
  return {sig, sigTxid, sigRound, pub, pubTxid, insc, boxes:boxes.length};
}

function render(app, r){
  if(!r.sig){
    out.innerHTML = `<div class="verdict"><span class="dot" style="background:var(--warn)"></span><span class="warn">No Falcon signature found</span></div>
      <p class="muted">No application-arg in the last 100 calls decodes as a Falcon-1024 signature. Check the app id, or this app may not use <code>falcon_verify</code>.</p>`;
    return;
  }
  const s=r.sig;
  const standard = s.compressed && s.logn===10;
  const verified = standard && r.insc; // sig present AND write-once inscription written => verify path passed
  const dot = verified ? "var(--ok)" : "var(--warn)";
  const headline = verified
    ? `<span class="ok">Post-quantum signature accepted on-chain</span>`
    : `<span class="warn">Falcon signature found — acceptance not confirmed</span>`;
  const detTxt = s.det ? `deterministic (0x80 wrapper bit set)` : `randomized`;
  out.innerHTML = `
    <div class="verdict"><span class="dot" style="background:${dot}"></span>${headline}</div>
    <p class="muted" style="margin:0 0 4px">${verified
      ? `The write-once inscription box exists — the contract writes it only after <code>falcon_verify</code> succeeds, so the opcode accepted this signature.`
      : `A Falcon-1024 signature is on chain, but no write-once inscription box was found to confirm the verify path ran.`}</p>
    <div class="grid">
      <div class="stat"><div class="k">Header byte</div><div class="v gold">${s.hex}</div></div>
      <div class="stat"><div class="k">Format</div><div class="v">${s.compressed?"compressed":"?"} · logn ${s.logn}</div></div>
      <div class="stat"><div class="k">Signature size</div><div class="v">${s.len} B</div></div>
      <div class="stat"><div class="k">Mode</div><div class="v">${detTxt}</div></div>
      <div class="stat"><div class="k">Public key</div><div class="v ${r.pub?"ok":"muted"}">${r.pub?"1793 B ✓":"not seen"}</div></div>
      <div class="stat"><div class="k">Write-once box</div><div class="v ${r.insc?"ok":"muted"}">${r.insc?"present ✓":"none"}</div></div>
    </div>
    <div class="links">
      ${r.sigTxid?`<a href="https://lora.algokit.io/testnet/transaction/${esc(r.sigTxid)}" target="_blank" rel="noopener">Signing txn ↗</a>`:""}
      <a href="https://lora.algokit.io/testnet/application/${esc(app)}" target="_blank" rel="noopener">App ${esc(app)} ↗</a>
    </div>`;
  note.innerHTML = `<b class="gold">How to read this.</b> <code>0xBA</code> = standard Falcon-1024 compressed header <code>0x3A</code> (high-nibble compressed, low-nibble logn 10) OR'd with a <code>0x80</code> bit and a <code>0x00</code> version byte that are <em>trelyan-pq's deterministic wrapper convention — not a NIST Falcon / FIPS-206 field</em>. The AVM <code>falcon_verify</code> opcode accepts it because it length-checks only the 1793-byte public key, not the signature. Algorand TestNet, unaudited.`;
}

async function run(){
  const app=(document.getElementById("app").value||"").trim().replace(/\D/g,"");
  if(!app){ out.innerHTML=`<p class="bad">Enter a numeric application id.</p>`; return; }
  btn.disabled=true; out.innerHTML=`<p class="muted"><span class="spin"></span> Querying Algorand TestNet…</p>`; note.textContent="";
  try{ render(app, await verify(app)); }
  catch(e){ out.innerHTML=`<p class="bad">Lookup failed: ${esc(e.message||e)}. The public indexer may be rate-limiting — try again.</p>`; }
  finally{ btn.disabled=false; }
}
btn.addEventListener("click", run);
document.getElementById("app").addEventListener("keydown", e=>{ if(e.key==="Enter") run(); });
run();
