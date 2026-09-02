/*!
 * g2-anchor-honesty — named gate for leftover PUBLIC displayed-vs-signed paint
 * on the two-layer Pages surfaces that G2 (gatePagesFalconClaim / g2-pages-honesty)
 * does not cover. Independent of G1 gradeOf and G2 gatePagesFalconClaim.
 *
 * PUBLIC LIE this gate locks (live GitHub Pages, same source on main):
 *   - docs/anchor.html (+ web/ + site-integration/pq copies):
 *       static Layer 2 "verified by falcon_verify";
 *       footnote "falcon_verify-gated inscribe()";
 *       Layer 1 "ML-DSA-87 present ✓" painted green from a truthy receipt.sig
 *       with no ml_dsa87.verify / falcon_verify / opcode / WASM.
 *   - docs/index.html (+ web/ + site-integration/pq copies):
 *       lede "Both layers now verify in your browser";
 *       step 3 "verified by the falcon_verify opcode";
 *       step 4 "They verify both layers in your browser … on-chain Falcon
 *       inscription straight from the chain".
 *
 * G2 LIE_PAINT_RE is /falcon_verify[- ]accepted/ and PUBLIC_SURFACES omits
 * these files/strings. Do not edit g2-pages-honesty.mjs.
 *
 * SOFTWARE (this file is the gate):
 *   gateAnchorHonesty(input) is TOTAL / fail-closed. It NEVER returns
 *   verified:true for a falcon_verify or ML-DSA result — this module does
 *   not run those primitives, does not fetch a chain as proof, and does
 *   not invent a TestNet/MainNet result.
 *
 * A mutation that restores the refused paints must FAIL the scanner.
 *
 * Domain: trelyan-g2-anchor-honesty-v1 (claim-hygiene gate; no signature).
 * Self-test: node g2-anchor-honesty.mjs
 */
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

export const GATE_NAME = 'gateAnchorHonesty';
export const G2_ANCHOR_DOMAIN = 'trelyan-g2-anchor-honesty-v1';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');

/** Sorted-key, type-distinct canon — byte-identical to the SDK reference. */
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

/**
 * Success-paint strings G2 does not match. "does not run falcon_verify" is
 * honest refusal copy and must NOT trip these (they require verified-by /
 * -gated / present-✓ / both-layers-verify).
 */
export const LIE_PAINT = [
  'verified by falcon_verify',
  'verified by the falcon_verify opcode',
  'falcon_verify-gated',
  'ML-DSA-87 present ✓',
  'Both layers now verify in your browser',
  'They verify both layers in your browser',
  'on-chain Falcon inscription straight from the chain',
];

const LIE_PAINT_RE = [
  /verified by the\s*(?:<code>)?falcon_verify/i,
  /verified by\s*(?:<code>)?falcon_verify/i,
  /falcon_verify(?:<\/code>)?[- ]gated/i,
  /ML-DSA-87 present\s*[✓✔]/,
  /Both layers now verify in your browser/i,
  /They verify both layers in your browser/i,
  /verify both layers in your browser/i,
  /on-chain Falcon inscription straight from the chain/i,
];

/** Green present-as-valid: truthy sig field paints ML-DSA-87 present ✓ / class ok. */
const PRESENT_AS_VALID_RE = [
  /ML-DSA-87 present\s*[✓✔]/,
  /\(sig\s*\?\s*"ok"\s*:\s*"warn"\)[\s\S]{0,120}ML-DSA-87 present/,
  /sig\s*\?\s*"ML-DSA-87 present\s*[✓✔]/,
];

/** Real primitive markers — none of these exist on the Pages surfaces this gate covers. */
const FALCON_PRIMITIVE_RE = [
  /\bfalconVerifyRan\b/,
  /\bopcodeRan\b/,
  /\bwasmRan\b/,
  /\bWebAssembly\b/,
  /\bfalcon_verify\s*\(/,
];
const MLDSA_VERIFY_RE = /\bml_dsa87\.verify\s*\(/;

const ANCHOR_SURFACES = [
  'docs/anchor.html',
  'web/anchor.html',
  'site-integration/pq/anchor.html',
  'site-integration/pq/js/anchor.js',
];
const INDEX_SURFACES = [
  'docs/index.html',
  'web/index.html',
  'site-integration/pq/index.html',
];
export const PUBLIC_SURFACES = ANCHOR_SURFACES.concat(INDEX_SURFACES);

/** Honest copy the public pages must keep after the refuse. */
const ANCHOR_HONEST_RE = [
  /does not run\s*(?:<code>)?falcon_verify/i,
  /does not verify ML-DSA/i,
  /recognized/i,
  /inscribe/i,
  /32-byte commit/i,
  /sth-verify\.html/,
  /sig field/i,
];
const INDEX_HONEST_RE = [
  /does not run\s*(?:the\s*)?(?:<code>)?falcon_verify/i,
  /sth-verify\.html/,
  /recognized/i,
  /inscribe/i,
  /32-byte commit/i,
];

function norm(s) { return String(s == null ? '' : s); }

export function paintsFalconVerifySuccess(text) {
  const t = norm(text);
  if (!t) return false;
  return LIE_PAINT_RE.some((re) => re.test(t));
}

export function paintsMldsaPresentAsValid(text) {
  const t = norm(text);
  if (!t) return false;
  return PRESENT_AS_VALID_RE.some((re) => re.test(t));
}

export function hasFalconPrimitive(text) {
  const t = norm(text);
  return FALCON_PRIMITIVE_RE.some((re) => re.test(t));
}

export function hasMldsaVerify(text) {
  return MLDSA_VERIFY_RE.test(norm(text));
}

/**
 * scanPublicPaint(source) — find leftover falcon_verify / present-✓ /
 * both-layers-verify paints. Does not fetch a chain. Does not run Falcon
 * or ML-DSA.
 */
export function scanPublicPaint(source) {
  try {
    const text = norm(source);
    const paints = [];
    for (const re of LIE_PAINT_RE) {
      if (re.test(text)) paints.push(re.source);
    }
    const presentAsValid = paintsMldsaPresentAsValid(text);
    const falconPaint = paintsFalconVerifySuccess(text);
    const primitive = hasFalconPrimitive(text);
    const mldsaVerify = hasMldsaVerify(text);
    const falconPaintWithoutPrimitive = falconPaint && !primitive;
    const presentWithoutVerify = presentAsValid && !mldsaVerify;
    const lie = paints.length > 0 || presentAsValid || falconPaintWithoutPrimitive || presentWithoutVerify;
    return {
      lie,
      paints,
      presentAsValid,
      falconPaintWithoutPrimitive,
      presentWithoutVerify,
      falconPrimitive: primitive,
      mldsaVerify,
    };
  } catch {
    return { lie: true, paints: ['scan-exception'], presentAsValid: false, falconPaintWithoutPrimitive: false, presentWithoutVerify: false, falconPrimitive: false, mldsaVerify: false };
  }
}

function stripTags(s) { return norm(s).replace(/<[^>]+>/g, ''); }

function missingHonest(rel, text) {
  const plain = stripTags(text);
  const need = ANCHOR_SURFACES.includes(rel) ? ANCHOR_HONEST_RE : INDEX_HONEST_RE;
  return need.filter((re) => !re.test(text) && !re.test(plain)).map((re) => re.source);
}

/**
 * gateAnchorHonesty(input) — named gate. TOTAL / fail-closed. Never throws.
 * Never returns verified:true for a falcon_verify or ML-DSA result.
 *
 * `verified` here would mean "the painted opcode-accepted / present-✓-as-valid
 * / both-layers-verify claim is allowed". It is always false. A lie paint
 * without a primitive is REFUSED.
 */
export function gateAnchorHonesty(input) {
  try {
    if (input == null || typeof input !== 'object' || Array.isArray(input)) return { verified: false, refuse: true, reason: 'shape', gate: GATE_NAME };
    if (input.inventedChainResult === true || input.testnetResult === true || input.mainnetResult === true) {
      return { verified: false, refuse: true, reason: 'INVENTED_CHAIN_RESULT', gate: GATE_NAME };
    }
    const painted = norm(input.paintedClaim || input.paint || '');
    const source = norm(input.source);
    const combined = painted + '\n' + source;
    const scan = scanPublicPaint(combined);
    const falconRan = input.falconVerifyRan === true || input.opcodeRan === true || input.wasmRan === true;
    const mldsaRan = input.mlDsaVerifyRan === true || input.verifyRan === true;
    if (scan.lie && !falconRan && !mldsaRan) {
      let reason = 'PAINT_WITHOUT_PRIMITIVE';
      if (scan.presentAsValid || /ML-DSA-87 present/i.test(combined)) reason = 'PRESENT_AS_VALID';
      if (/both layers/i.test(combined) && /verify.{0,40}in your browser/i.test(combined)) reason = 'BOTH_LAYERS_VERIFY_PAINT';
      if (/verified by/i.test(combined) && /falcon_verify/i.test(combined)) reason = 'FALCON_VERIFY_PAINT_WITHOUT_OPCODE';
      if (/falcon_verify/.test(combined) && /gated/i.test(combined)) reason = 'FALCON_VERIFY_GATED_PAINT';
      return { verified: false, refuse: true, reason, gate: GATE_NAME, scan };
    }
    if (scan.lie && (falconRan || mldsaRan)) {
      // This module still does not run those primitives; a caller asserting
      // they ran is not a verify result we will rubber-stamp.
      return { verified: false, refuse: true, reason: 'MODULE_DOES_NOT_RUN_PRIMITIVE', gate: GATE_NAME };
    }
    return {
      verified: false,
      refuse: false,
      allowed: true,
      reason: 'no opcode-accepted / present-✓-as-valid / both-layers-verify paint',
      gate: GATE_NAME,
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
    const text = readFileSync(p, 'utf8');
    const r = scanPublicPaint(text);
    const honestGap = missingHonest(rel, text);
    if (r.lie || honestGap.length) findings.push({ file: rel, ...r, honestGap });
  }
  return { ok: findings.length === 0, findings, scanned: PUBLIC_SURFACES.length };
}

export { canon };

/* ---------- self-test: node g2-anchor-honesty.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0;
  const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  function defectIfVerifiedTrue(r, label) {
    const lie = !!(r && r.verified === true);
    const refused = !!(r && r.verified === false && r.refuse === true);
    console.log('OBSERVED ' + label + ' => ' + JSON.stringify({ verified: r && r.verified, refuse: r && r.refuse, reason: r && r.reason }) + (lie ? '  DEFECT verified:true' : '  REFUSE'));
    if (lie) {
      fail++;
      console.error('DEFECT: ' + label + ' returned verified:true (this module does not run falcon_verify / ML-DSA)');
      return;
    }
    ok(refused, label + ' refuses (verified:false, refuse:true)');
  }

  // FAIL-TEST: Layer 2 success paint while no falconVerifyRan / opcode / WASM
  defectIfVerifiedTrue(
    gateAnchorHonesty({ paintedClaim: 'verified by falcon_verify', falconVerifyRan: false, opcodeRan: false, wasmRan: false }),
    'FAIL-TEST gateAnchorHonesty(paint=verified by falcon_verify, no primitive)'
  );
  defectIfVerifiedTrue(
    gateAnchorHonesty({ paintedClaim: 'A ✓ confirms Layer 2 only via a falcon_verify-gated inscribe() call', falconVerifyRan: false, opcodeRan: false, wasmRan: false }),
    'FAIL-TEST gateAnchorHonesty(paint=falcon_verify-gated, no primitive)'
  );
  defectIfVerifiedTrue(
    gateAnchorHonesty({ paintedClaim: 'verified by the falcon_verify opcode', falconVerifyRan: false, opcodeRan: false, wasmRan: false }),
    'FAIL-TEST gateAnchorHonesty(paint=verified by the falcon_verify opcode, no primitive)'
  );

  // FAIL-TEST: Layer 1 present-✓ from a truthy sig field, no verify()
  defectIfVerifiedTrue(
    gateAnchorHonesty({ paintedClaim: 'ML-DSA-87 present ✓ (2592 B)', source: 'var sig=(s.receipt||{}).sig; +(sig?"ok":"warn")+(sig?"ML-DSA-87 present ✓":"none")', mlDsaVerifyRan: false, verifyRan: false }),
    'FAIL-TEST gateAnchorHonesty(paint=ML-DSA-87 present ✓ from truthy sig, no verify())'
  );

  // FAIL-TEST: index lede / step 4 both-layers-verify paint
  defectIfVerifiedTrue(
    gateAnchorHonesty({ paintedClaim: 'Both layers now verify in your browser: the ML-DSA-87 tree-head signature (Layer 1) and the Falcon-1024 on-chain inscription (Layer 2).', falconVerifyRan: false, mlDsaVerifyRan: false }),
    'FAIL-TEST gateAnchorHonesty(paint=Both layers now verify in your browser)'
  );
  defectIfVerifiedTrue(
    gateAnchorHonesty({ paintedClaim: 'They verify both layers in your browser and the on-chain Falcon inscription straight from the chain', falconVerifyRan: false }),
    'FAIL-TEST gateAnchorHonesty(paint=They verify both layers in your browser)'
  );

  // FAIL-TEST: inventing a chain result is refused
  defectIfVerifiedTrue(
    gateAnchorHonesty({ paintedClaim: 'verified by falcon_verify', inventedChainResult: true, testnetResult: true }),
    'FAIL-TEST gateAnchorHonesty(invented TestNet result)'
  );

  // TOTAL / fail-closed — never verified:true
  const garbage = [null, undefined, 0, 1, '', 'verified', [], { verified: true }, { sig: 'deadbeef' }, { paint: 1 }];
  for (const g of garbage) {
    const r = gateAnchorHonesty(g);
    ok(r && r.verified === false, 'TOTAL: ' + (g === undefined ? 'undefined' : JSON.stringify(g)).slice(0, 40) + ' -> verified:false');
    if (g == null || typeof g !== 'object' || Array.isArray(g)) {
      ok(r.refuse === true, 'TOTAL: non-object -> refuse:true');
    }
  }
  ok(gateAnchorHonesty({}).verified === false && gateAnchorHonesty({}).refuse === false,
    'empty honest object is not a falcon_verify / ML-DSA pass');

  // Honest copy is allowed as a page, but is NOT verified:true
  const honest = gateAnchorHonesty({
    paintedClaim: 'This UI does not run falcon_verify and does not verify ML-DSA. A match is recognized app-id + inscribe selector + 32-byte commit; a truthy sig field is presence only. Layer 1 verify lives at sth-verify.html.',
    falconVerifyRan: false, opcodeRan: false, wasmRan: false, mlDsaVerifyRan: false,
  });
  ok(honest.verified === false && honest.refuse === false && honest.allowed === true,
    'honest heuristic/presence copy is allowed and is not an opcode / ML-DSA result');

  // FAIL-TEST: mutation restoring the live paints must fail the scanner
  const restoredAnchor = [
    '<p>The tree-head commitment, write-once on a public chain, verified by <code>falcon_verify</code>.</p>',
    '+"<div class=\\"v \'+(sig?"ok":"warn")+\'">"+(sig?"ML-DSA-87 present ✓ ("+sig.length/2+" B)":"none")',
    'A ✓ confirms Layer 2 only: a recognized TRELYAN contract inscribed this exact tree-head commitment via a <code>falcon_verify</code>-gated <code>inscribe()</code> call',
  ].join('\n');
  const mutA = scanPublicPaint(restoredAnchor);
  console.log('OBSERVED FAIL-TEST mutation restoring anchor falcon_verify / present-✓ paint => ' + JSON.stringify({ lie: mutA.lie, presentAsValid: mutA.presentAsValid, falconPaintWithoutPrimitive: mutA.falconPaintWithoutPrimitive, paints: mutA.paints.length }) + (mutA.lie ? '  CATCH' : '  DEFECT miss'));
  ok(mutA.lie === true && mutA.presentAsValid === true && mutA.falconPaintWithoutPrimitive === true,
    'FAIL-TEST: mutation restoring verified-by-falcon_verify + falcon_verify-gated + ML-DSA-87 present ✓ is a lie');
  defectIfVerifiedTrue(
    gateAnchorHonesty({ source: restoredAnchor, falconVerifyRan: false, opcodeRan: false, wasmRan: false, mlDsaVerifyRan: false }),
    'FAIL-TEST gateAnchorHonesty(mutated anchor.html source)'
  );

  const restoredIndex = [
    '<strong>Both layers now verify in your browser</strong>: the ML-DSA-87 tree-head signature (Layer 1) and the Falcon-1024 on-chain inscription (Layer 2).',
    'verified by the <code>falcon_verify</code> opcode.',
    'They verify <b>both layers in your browser</b> — the ML-DSA-87 signature against a pinned key, and the on-chain Falcon inscription straight from the chain.',
  ].join('\n');
  const mutI = scanPublicPaint(restoredIndex);
  console.log('OBSERVED FAIL-TEST mutation restoring index both-layers / opcode paint => ' + JSON.stringify({ lie: mutI.lie, paints: mutI.paints.length }) + (mutI.lie ? '  CATCH' : '  DEFECT miss'));
  ok(mutI.lie === true && mutI.paints.length >= 3,
    'FAIL-TEST: mutation restoring both-layers-verify + verified-by-the-falcon_verify-opcode is a lie');
  defectIfVerifiedTrue(
    gateAnchorHonesty({ source: restoredIndex, falconVerifyRan: false }),
    'FAIL-TEST gateAnchorHonesty(mutated index.html source)'
  );

  // Shipped public surfaces: refuse leftover paints; require honest copy
  const shipped = scanShippedSurfaces();
  if (!shipped.ok) {
    fail++;
    console.error('FAIL: shipped public surfaces still paint falcon_verify / present-✓ / both-layers-verify, or dropped honest copy:\n   ' + shipped.findings.map((f) => f.file
      + (f.reason ? ' (' + f.reason + ')' : '')
      + (f.paints && f.paints.length ? ' paints=' + f.paints.join('|') : '')
      + (f.presentAsValid ? ' present-as-valid' : '')
      + (f.falconPaintWithoutPrimitive ? ' falcon-paint-no-primitive' : '')
      + (f.honestGap && f.honestGap.length ? ' missing-honest=' + f.honestGap.join('|') : '')).join('\n   '));
  } else {
    pass++;
    console.log('OBSERVED shipped public surfaces (' + shipped.scanned + ') refuse falcon_verify / present-✓ / both-layers-verify paint  PASS');
  }

  // Distinct from G1 / G2: this module does not export gradeOf or gatePagesFalconClaim
  ok(typeof gateAnchorHonesty === 'function' && GATE_NAME === 'gateAnchorHonesty', 'named gate is gateAnchorHonesty (not gradeOf, not gatePagesFalconClaim)');
  ok(G2_ANCHOR_DOMAIN === 'trelyan-g2-anchor-honesty-v1', 'unique domain string trelyan-g2-anchor-honesty-v1');
  ok(canon({ b: 1, a: 2 }) === '{"a":2,"b":1}', 'canon() is sorted-key / type-distinct');
  ok(PUBLIC_SURFACES.length === 7 && PUBLIC_SURFACES.every((f) => /anchor\.(html|js)$|index\.html$/.test(f)),
    'PUBLIC_SURFACES is the anchor+index Pages copies plus site-integration js/anchor.js (independent of G2 verify-live/pqbadge)');

  console.log('g2-anchor-honesty self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /g2-anchor-honesty\.mjs$/.test(process.argv[1] || '')) selfTest();
