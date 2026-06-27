/*!
 * worker.mjs — Cloudflare-Worker-style hosted endpoint for the TRELYAN Quantum-Safe Scorecard.
 * OWNER-GATED: prepared, NOT deployed. See DEPLOY.md. Routes:
 *   GET  /                 -> service info
 *   POST /scan             -> { files:[{name,text}], full?, policy? }  => scorecard (+full=CBOM, paid)
 *   GET  /badge?grade=&score= -> shields.io endpoint JSON for the README badge (no SVG authored here)
 * Production note: persist scan results per owner/repo (e.g. Workers KV) so /badge/:owner/:repo reflects the
 * latest scan; gate the paid `full` tier behind an API key (env). This reference keeps it stateless.
 */
import { handleScan, scorecardBadge, PREVIEW_NOTICE } from '../pqcbom-server.mjs';
import { verify as verifyArtifact } from '../pqverify-api.mjs';

const CORS = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };
// Evidence-Pack signing key (ML-DSA-87) is OWNER-PROVISIONED at deploy (env.REPORT_SIGNING_SK / _PK hex). Absent =>
// the paid Evidence Pack is returned UNSIGNED with a reason; never silently "signed".

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });

    if (url.pathname === '/scan' && req.method === 'POST') {
      let body; try { body = await req.json(); } catch { return json({ error: 'bad JSON' }, 400); }
      const { files, full, evidencePack, meta, policy } = body || {};
      // paid tier (full CBOM / Evidence Pack) requires an API key (owner provisions env.PAID_KEYS)
      const auth = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
      const allowPaid = (full || evidencePack) && env && env.PAID_KEYS && String(env.PAID_KEYS).split(',').includes(auth);
      const signer = signerFromEnv(env); // owner-provisioned; null => Evidence Pack returned unsigned + reason
      const out = handleScan(files || [], { full: !!(allowPaid && full), evidencePack: !!(allowPaid && evidencePack), meta, signer, policy });
      if (out.evidence_pack && !signer) out.evidence_pack_unsigned_reason = 'REPORT_SIGNING_SK not provisioned (owner deploy step)';
      return json(out);
    }
    if (url.pathname === '/verify' && req.method === 'POST') { // public, free: verify any TRELYAN artifact
      let body; try { body = await req.json(); } catch { return json({ ok: false, error: 'bad JSON' }, 400); }
      return json(await verifyArtifact(body));
    }
    if (url.pathname.startsWith('/badge')) {
      const grade = (url.searchParams.get('grade') || 'A').toUpperCase();
      const score = Number(url.searchParams.get('score') || 0);
      return json(scorecardBadge({ letter: grade, score }));
    }
    return json({ ok: true, service: 'trelyan-quantum-safe-scorecard', notice: PREVIEW_NOTICE, tiers: { free: '/badge + /scan (scorecard) + /verify (verify any TRELYAN artifact)', paid: '/scan {full:true | evidencePack:true} + Bearer key (CBOM / signed Evidence Pack)' } });
  },
};
function json(o, status = 200) { return new Response(JSON.stringify(o), { status, headers: CORS }); }
// owner provisions env.REPORT_SIGNING_SK / REPORT_SIGNING_PK as hex (an ML-DSA-87 keypair) to enable signed Evidence Packs.
function signerFromEnv(env) {
  try { if (env && env.REPORT_SIGNING_SK && env.REPORT_SIGNING_PK) return { secretKey: hexToU8(env.REPORT_SIGNING_SK), publicKey: hexToU8(env.REPORT_SIGNING_PK) }; } catch {}
  return null;
}
function hexToU8(h) { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return b; }
