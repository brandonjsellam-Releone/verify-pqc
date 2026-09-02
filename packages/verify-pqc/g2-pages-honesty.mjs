/*!
 * g2-pages-honesty — TRELYAN apex G2 named gate (distinct from G1 gradeOf).
 *
 * PUBLIC LIE this gate locks: GitHub Pages / pqbadge / verify-unified painted
 * "post-quantum verified" / "falcon_verify-accepted" when the browser only had
 *   verified = standard && insc && recognized
 * (header nibble/length + i_ box + allowlist 763809096/764917520). No opcode,
 * no WASM, no falcon_verify result.
 *
 * SOFTWARE (this file is the gate):
 *   gatePagesFalconClaim(input) is TOTAL / fail-closed. A paint of
 *   post-quantum-verified / falcon_verify-accepted when only those heuristic
 *   conjuncts are true is REFUSED ({verified:false, refuse:true}).
 *   This module does not implement Falcon, does not run falcon_verify, and
 *   does not invent a TestNet/MainNet result.
 *
 * A mutation that restores the lie (in the gate return, or in a public
 * page/badge source string) must FAIL.
 *
 * Domain: trelyan-g2-pages-honesty-v1 (claim-hygiene gate; no signature).
 * Self-test: node g2-pages-honesty.mjs
 */
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

export const GATE_NAME = 'gatePagesFalconClaim';
export const G2_DOMAIN = 'trelyan-g2-pages-honesty-v1';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');

/** Success-paint strings that claim an opcode / PQ-verified result. */
export const LIE_PAINT = [
  'post-quantum verified on-chain',
  'post-quantum signature accepted on-chain',
  'so the opcode accepted this signature',
  'falcon_verify accepted this signature',
  'shows whether falcon_verify accepted it',
  'checks whether falcon_verify accepted it',
  'proves the post-quantum signature was accepted on-chain',
];

const LIE_PAINT_RE = [
  /post-quantum verified/i,
  /post-quantum signature accepted on-chain/i,
  /so the opcode accepted this signature/i,
  /falcon_verify[- ]accepted/i,
  /shows whether falcon_verify accepted it/i,
  /checks whether <code>falcon_verify<\/code> accepted it/i,
  /checks whether falcon_verify accepted it/i,
  /proves the post-quantum signature was accepted on-chain/i,
];

/** Heuristic assigned to a `verified` verdict (the conjuncts, not an opcode). */
const HEURISTIC_AS_VERIFIED_RE = [
  /verified\s*=\s*standard\s*&&\s*r\.insc\s*&&\s*recognized/,
  /verified\s*:\s*!!\s*\(\s*sig\s*&&\s*insc\s*&&\s*recognized\s*\)/,
  /verified\s*:\s*!!\s*\(\s*sig\s*&&\s*insc\s*\)/,
  /var\s+verified\s*=\s*!!\s*\(\s*sigInfo[\s\S]{0,160}recognized\s*\)/,
];

const PUBLIC_SURFACES = [
  'docs/verify-live.html',
  'docs/pqbadge.js',
  'docs/verify-unified.html',
  'docs/verify-section.snippet.html',
  'docs/pqbadge-demo.html',
  'web/verify-live.html',
  'web/pqbadge.js',
  'web/verify-unified.html',
  'web/verify-section.snippet.html',
  'web/pqbadge-demo.html',
  'site-integration/pq/verify-live.html',
  'site-integration/pq/verify-unified.html',
  'site-integration/pq/pqbadge-demo.html',
  'site-integration/pq/js/verify-live.js',
  'site-integration/pq/js/pqbadge.js',
  'site-integration/pq/js/verify-unified.js',
  'packages/verify-pqc/index.js',
];

function norm(s) { return String(s == null ? '' : s); }

/** True if `text` is a PQ-verified / falcon_verify-accepted success paint. */
export function paintsFalconVerifyAccepted(text) {
  const t = norm(text);
  if (!t) return false;
  return LIE_PAINT_RE.some((re) => re.test(t));
}

/** True if source assigns the public heuristic conjuncts to a `verified` verdict. */
export function assignsHeuristicToVerified(text) {
  const t = norm(text);
  if (!t) return false;
  return HEURISTIC_AS_VERIFIED_RE.some((re) => re.test(t));
}

/**
 * scanPublicPaint(source) — find lie paints / heuristic-as-verified assignments
 * in a page or badge source string. Does not fetch a chain. Does not run Falcon.
 */
export function scanPublicPaint(source) {
  try {
    const text = norm(source);
    const paints = [];
    for (const re of LIE_PAINT_RE) {
      if (re.test(text)) paints.push(re.source);
    }
    const heuristicAsVerified = assignsHeuristicToVerified(text);
    const lie = paints.length > 0 || heuristicAsVerified;
    return { lie, paints, heuristicAsVerified };
  } catch {
    return { lie: true, paints: ['scan-exception'], heuristicAsVerified: false };
  }
}

/**
 * gatePagesFalconClaim(input) — G2 named gate. TOTAL / fail-closed. Never throws.
 *
 * A page/badge paint of "post-quantum verified" / "falcon_verify-accepted" when
 * only the heuristic conjuncts (standard header, i_ box, recognized allowlist)
 * are true — and falcon_verify / opcode / WASM did not run — is REFUSED.
 *
 * This function never returns verified:true for a falcon_verify result: it does
 * not implement Falcon, does not run the opcode, and does not invent a chain
 * result. `verified` here means "the painted falcon_verify-accepted claim is
 * allowed". It is false on the lie and on garbage.
 */
export function gatePagesFalconClaim(input) {
  try {
    if (input == null || typeof input !== 'object') return { verified: false, refuse: true, reason: 'shape', gate: GATE_NAME };
    const h = input.heuristic && typeof input.heuristic === 'object' ? input.heuristic : {};
    const standard = h.standard === true;
    const insc = h.insc === true;
    const recognized = h.recognized === true;
    const heuristicOnly = standard && insc && recognized
      && input.opcodeRan !== true
      && input.wasmRan !== true
      && input.falconVerifyRan !== true;
    const painted = norm(input.paintedClaim || input.paint || '');
    const source = norm(input.source);
    const paintLie = paintsFalconVerifyAccepted(painted) || paintsFalconVerifyAccepted(source);
    const assignLie = assignsHeuristicToVerified(source);
    if (input.inventedChainResult === true || input.testnetResult === true || input.mainnetResult === true) {
      return { verified: false, refuse: true, reason: 'INVENTED_CHAIN_RESULT', gate: GATE_NAME };
    }
    if (heuristicOnly && (paintLie || assignLie)) {
      return { verified: false, refuse: true, reason: 'HEURISTIC_AS_FALCON_VERIFY', gate: GATE_NAME, heuristicOnly: true };
    }
    if (paintLie && input.falconVerifyRan !== true) {
      return { verified: false, refuse: true, reason: 'PAINT_WITHOUT_OPCODE', gate: GATE_NAME };
    }
    if (assignLie) {
      return { verified: false, refuse: true, reason: 'HEURISTIC_ASSIGNED_TO_VERIFIED', gate: GATE_NAME };
    }
    return {
      verified: false,
      refuse: false,
      allowed: true,
      reason: 'heuristic-only is not an opcode result',
      gate: GATE_NAME,
      heuristicOnly: !!(standard && insc && recognized),
    };
  } catch {
    return { verified: false, refuse: true, reason: 'exception', gate: GATE_NAME };
  }
}

/** Scan shipped public surfaces. Missing files are a FAIL (surface dropped). */
export function scanShippedSurfaces() {
  const findings = [];
  for (const rel of PUBLIC_SURFACES) {
    const p = join(repoRoot, rel);
    if (!existsSync(p)) {
      findings.push({ file: rel, lie: true, reason: 'missing' });
      continue;
    }
    const r = scanPublicPaint(readFileSync(p, 'utf8'));
    if (r.lie) findings.push({ file: rel, ...r });
  }
  return { ok: findings.length === 0, findings, scanned: PUBLIC_SURFACES.length };
}

/* ---------- self-test: node g2-pages-honesty.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0;
  const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  const heuristic = { standard: true, insc: true, recognized: true };

  function defectIfVerifiedTrue(r, label) {
    const lie = !!(r && r.verified === true);
    const refused = !!(r && r.verified === false && r.refuse === true);
    console.log('OBSERVED ' + label + ' => ' + JSON.stringify({ verified: r && r.verified, refuse: r && r.refuse, reason: r && r.reason }) + (lie ? '  DEFECT verified:true' : '  REFUSE'));
    if (lie) {
      fail++;
      console.error('DEFECT: ' + label + ' painted falcon_verify-accepted / post-quantum verified from heuristic-only conjuncts');
      return;
    }
    ok(refused, label + ' refuses (verified:false, not a falcon_verify result)');
  }

  // FAIL-TEST: named gate must FAIL the live-page lie (heuristic conjuncts + PQ-verified paint)
  defectIfVerifiedTrue(
    gatePagesFalconClaim({ heuristic, paintedClaim: 'post-quantum verified on-chain', opcodeRan: false, wasmRan: false, falconVerifyRan: false }),
    'FAIL-TEST gatePagesFalconClaim(heuristic-only, paint=post-quantum verified)'
  );
  defectIfVerifiedTrue(
    gatePagesFalconClaim({ heuristic, paintedClaim: 'falcon_verify-accepted', opcodeRan: false, wasmRan: false, falconVerifyRan: false }),
    'FAIL-TEST gatePagesFalconClaim(heuristic-only, paint=falcon_verify-accepted)'
  );
  defectIfVerifiedTrue(
    gatePagesFalconClaim({ heuristic, paintedClaim: 'Post-quantum signature accepted on-chain', opcodeRan: false, wasmRan: false, falconVerifyRan: false }),
    'FAIL-TEST gatePagesFalconClaim(heuristic-only, paint=signature accepted on-chain)'
  );
  defectIfVerifiedTrue(
    gatePagesFalconClaim({ heuristic, paintedClaim: 'so the opcode accepted this signature', opcodeRan: false, wasmRan: false, falconVerifyRan: false }),
    'FAIL-TEST gatePagesFalconClaim(heuristic-only, paint=opcode accepted)'
  );

  // FAIL-TEST: inventing a chain result is refused (this gate never runs an indexer as proof)
  defectIfVerifiedTrue(
    gatePagesFalconClaim({ heuristic, paintedClaim: 'post-quantum verified on-chain', inventedChainResult: true, testnetResult: true }),
    'FAIL-TEST gatePagesFalconClaim(invented TestNet result)'
  );

  // TOTAL / fail-closed
  ok(gatePagesFalconClaim(null).verified === false, 'TOTAL: null -> verified false');
  ok(gatePagesFalconClaim(undefined).verified === false, 'TOTAL: undefined -> verified false');
  ok(gatePagesFalconClaim('verified').verified === false, 'TOTAL: string -> verified false');
  ok(gatePagesFalconClaim({}).verified === false, 'TOTAL: {} -> verified false (never an opcode pass)');

  // Honest heuristic paint is allowed as a page, but is NOT verified:true
  const honest = gatePagesFalconClaim({
    heuristic, paintedClaim: 'Heuristic match — this page does not run falcon_verify',
    opcodeRan: false, wasmRan: false, falconVerifyRan: false,
  });
  ok(honest.verified === false && honest.refuse === false && honest.allowed === true,
    'honest heuristic copy is allowed and is not falcon_verify-accepted');

  // Mutation restoring the live-page assignment + accepted paint must FAIL the scanner
  const restoredLie = [
    'const verified = standard && r.insc && recognized; // only a recognized TRELYAN contract gates its i_ box on falcon_verify',
    'const headline = verified ? `<span class="ok">Post-quantum signature accepted on-chain</span>` : "";',
    'App 763809096 writes the write-once box only after falcon_verify succeeds, so the opcode accepted this signature.',
  ].join('\n');
  const mutated = scanPublicPaint(restoredLie);
  console.log('OBSERVED FAIL-TEST mutation restoring heuristic-as-verified + accepted paint => ' + JSON.stringify({ lie: mutated.lie, heuristicAsVerified: mutated.heuristicAsVerified, paints: mutated.paints.length }) + (mutated.lie ? '  CATCH' : '  DEFECT miss'));
  ok(mutated.lie === true && mutated.heuristicAsVerified === true && mutated.paints.length > 0,
    'FAIL-TEST: mutation restoring verified=standard&&insc&&recognized + accepted paint is a lie');
  defectIfVerifiedTrue(
    gatePagesFalconClaim({ heuristic, source: restoredLie, opcodeRan: false, wasmRan: false, falconVerifyRan: false }),
    'FAIL-TEST gatePagesFalconClaim(mutated live-page source)'
  );

  const badgeLie = "if (r.sig && r.insc && recognized) render(el, 'pqb-v', 'post-quantum verified on-chain', 'write-once inscription');";
  ok(scanPublicPaint(badgeLie).lie === true, 'FAIL-TEST: mutation restoring pqbadge verified-on-chain paint is a lie');
  defectIfVerifiedTrue(
    gatePagesFalconClaim({ heuristic, source: badgeLie, paintedClaim: 'post-quantum verified on-chain', opcodeRan: false, wasmRan: false, falconVerifyRan: false }),
    'FAIL-TEST gatePagesFalconClaim(mutated pqbadge source)'
  );

  // Shipped public surfaces must not paint the lie
  const shipped = scanShippedSurfaces();
  if (!shipped.ok) {
    fail++;
    console.error('FAIL: shipped public surfaces still paint heuristic as falcon_verify-accepted:\n   ' + shipped.findings.map((f) => f.file + (f.reason ? ' (' + f.reason + ')' : '') + (f.paints && f.paints.length ? ' paints=' + f.paints.join('|') : '') + (f.heuristicAsVerified ? ' heuristic-as-verified' : '')).join('\n   '));
  } else {
    pass++;
    console.log('OBSERVED shipped public surfaces (' + shipped.scanned + ') have no PQ-verified / falcon_verify-accepted paint from the heuristic  PASS');
  }

  // Distinct from G1: this module does not export / call gradeOf
  ok(typeof gatePagesFalconClaim === 'function' && GATE_NAME === 'gatePagesFalconClaim', 'named gate is gatePagesFalconClaim (G2, not gradeOf)');
  ok(G2_DOMAIN === 'trelyan-g2-pages-honesty-v1', 'unique G2 domain string');

  console.log('g2-pages-honesty self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /g2-pages-honesty\.mjs$/.test(process.argv[1] || '')) selfTest();
