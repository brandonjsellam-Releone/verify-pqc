/*!
 * g2-readme-honesty — named gate for leftover PUBLIC displayed-vs-signed paint
 * on shipped README surfaces that G1 gradeOf, G2 gatePagesFalconClaim, and
 * G2 gateAnchorHonesty do not cover. Independent of those gates.
 *
 * PUBLIC LIE this gate locks (npm + GitHub README on main today):
 *   packages/verify-pqc/README.md (in package.json "files"; ships on npm):
 *     verifyOnChain example comments
 *       { verified: true, signature: { headerHex:'0xba', ... } }
 *     Honest framing:
 *       "i_ box as proof that falcon_verify accepted the signature"
 *   verifyOnChain on main only does the heuristic (Falcon-shaped compressed
 *   header + i_ box + allowlist). It does not run falcon_verify.
 *
 * Do not edit g2-pages-honesty.mjs or g2-anchor-honesty.mjs.
 * Do not treat verifyThrondarStrong `{ verified: true }` as this lie — that
 * path actually calls noble ML-DSA.
 *
 * SOFTWARE (this file is the gate):
 *   gateReadmeFalconClaim(input) is TOTAL / fail-closed. It NEVER returns
 *   verified:true for a falcon_verify result — this module does not run
 *   falcon_verify, does not run WASM, does not fetch a chain as proof, and
 *   does not invent a TestNet/MainNet result.
 *
 * A mutation that restores the README lie must FAIL the scanner.
 *
 * Domain: trelyan-g2-readme-honesty-v1 (claim-hygiene gate; no signature).
 * Self-test: node g2-readme-honesty.mjs
 */
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

export const GATE_NAME = 'gateReadmeFalconClaim';
export const G2_README_DOMAIN = 'trelyan-g2-readme-honesty-v1';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');

/** Sorted-key, type-distinct canon — byte-identical to the SDK reference. */
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

/**
 * Success-paint strings that claim verifyOnChain returned a falcon_verify
 * result from the i_ box heuristic. Honest copy ("heuristicMatch only; this
 * function does not run falcon_verify") must NOT trip these.
 */
export const LIE_PAINT = [
  "{ verified: true, signature: { headerHex:'0xba'",
  'i_ box as proof that falcon_verify accepted the signature',
];

const LIE_PAINT_RE = [
  /verified\s*:\s*true\s*,\s*signature\s*:\s*\{\s*headerHex\s*:\s*['"]0xba['"]/i,
  /i_`?\s+box as proof that[\s\n]+`?falcon_verify`?\s+accepted the signature/i,
  /i_\s+box as proof that\s+falcon_verify\s+accepted the signature/i,
];

/** Painted `{ verified: true }` as a falcon_verify / opcode result. */
const PAINTED_VERIFIED_TRUE_RE = /\{\s*verified\s*:\s*true\s*\}/;

/** verifyOnChain call whose nearby result comment paints verified:true. */
const VERIFY_ONCHAIN_RESULT_TRUE_RE = /await\s+verifyOnChain\s*\([\s\S]{0,200}?verified\s*:\s*true/;

/**
 * Shipped README surfaces. Missing files = FAIL (surface dropped).
 * Root + examples are scanned for the same verifyOnChain lie; they must
 * exist even when they currently do not copy it.
 */
export const README_SURFACES = [
  'packages/verify-pqc/README.md',
  'README.md',
  'packages/verify-pqc/examples/demo/README.md',
];

function norm(s) { return String(s == null ? '' : s); }

export function paintsVerifyOnChainVerifiedTrue(text) {
  const t = norm(text);
  if (!t) return false;
  return LIE_PAINT_RE[0].test(t) || VERIFY_ONCHAIN_RESULT_TRUE_RE.test(t);
}

export function paintsIBoxAsFalconProof(text) {
  const t = norm(text);
  if (!t) return false;
  return LIE_PAINT_RE[1].test(t) || LIE_PAINT_RE[2].test(t);
}

/**
 * scanReadmePaint(source) — find verifyOnChain `{ verified: true }` /
 * "i_ box as proof that falcon_verify accepted" paints.
 * Does not fetch a chain. Does not run Falcon.
 * Does not treat verifyThrondarStrong `{ verified: true }` as this lie.
 */
export function scanReadmePaint(source) {
  try {
    const text = norm(source);
    const paints = [];
    for (const re of LIE_PAINT_RE) {
      if (re.test(text)) paints.push(re.source);
    }
    const onChainVerifiedTrue = paintsVerifyOnChainVerifiedTrue(text);
    const iBoxAsProof = paintsIBoxAsFalconProof(text);
    const lie = paints.length > 0 || onChainVerifiedTrue || iBoxAsProof;
    return { lie, paints, onChainVerifiedTrue, iBoxAsProof };
  } catch {
    return { lie: true, paints: ['scan-exception'], onChainVerifiedTrue: false, iBoxAsProof: false };
  }
}

/**
 * gateReadmeFalconClaim(input) — named gate. TOTAL / fail-closed. Never throws.
 * Never returns verified:true for a falcon_verify result.
 *
 * `verified` here would mean "the painted verifyOnChain falcon_verify-accepted
 * / { verified: true } claim is allowed". It is always false. A heuristic-only
 * `{ verified: true }` paint is REFUSED.
 */
export function gateReadmeFalconClaim(input) {
  try {
    if (input == null || typeof input !== 'object' || Array.isArray(input)) {
      return { verified: false, refuse: true, reason: 'shape', gate: GATE_NAME };
    }
    if (input.inventedChainResult === true || input.testnetResult === true || input.mainnetResult === true) {
      return { verified: false, refuse: true, reason: 'INVENTED_CHAIN_RESULT', gate: GATE_NAME };
    }
    const painted = norm(input.paintedClaim || input.paint || '');
    const source = norm(input.source);
    const combined = painted + '\n' + source;
    const scan = scanReadmePaint(combined);
    const falconRan = input.falconVerifyRan === true || input.opcodeRan === true || input.wasmRan === true;
    const heuristicOnly = input.heuristicOnly === true
      || (input.falconVerifyRan !== true && input.opcodeRan !== true && input.wasmRan !== true);
    const paintedVerifiedTrue = PAINTED_VERIFIED_TRUE_RE.test(painted)
      || /^\s*\{\s*verified\s*:\s*true\s*\}\s*$/.test(painted)
      || (/\bverified\s*:\s*true\b/.test(painted) && !/heuristicMatch only/i.test(painted) && !/does not run\s+falcon_verify/i.test(painted));

    if (heuristicOnly && (scan.lie || paintedVerifiedTrue) && !falconRan) {
      let reason = 'HEURISTIC_AS_FALCON_VERIFY';
      if (scan.iBoxAsProof) reason = 'I_BOX_AS_FALCON_PROOF';
      if (scan.onChainVerifiedTrue || paintedVerifiedTrue) reason = 'HEURISTIC_AS_FALCON_VERIFY';
      return { verified: false, refuse: true, reason, gate: GATE_NAME, heuristicOnly: true, scan };
    }
    if ((scan.lie || paintedVerifiedTrue) && falconRan) {
      // This module still does not run falcon_verify; a caller asserting
      // it ran is not a verify result we will rubber-stamp.
      return { verified: false, refuse: true, reason: 'MODULE_DOES_NOT_RUN_PRIMITIVE', gate: GATE_NAME };
    }
    return {
      verified: false,
      refuse: false,
      allowed: true,
      reason: 'heuristic-only is not an opcode result',
      gate: GATE_NAME,
      heuristicOnly: heuristicOnly && !falconRan,
      canon: canon({ gate: GATE_NAME, domain: G2_README_DOMAIN }),
    };
  } catch {
    return { verified: false, refuse: true, reason: 'exception', gate: GATE_NAME };
  }
}

/** Scan shipped README surfaces. Missing files are a FAIL (surface dropped). */
export function scanShippedReadmes() {
  const findings = [];
  for (const rel of README_SURFACES) {
    const p = join(repoRoot, rel);
    if (!existsSync(p)) {
      findings.push({ file: rel, lie: true, reason: 'missing' });
      continue;
    }
    const r = scanReadmePaint(readFileSync(p, 'utf8'));
    if (r.lie) findings.push({ file: rel, ...r });
  }
  return { ok: findings.length === 0, findings, scanned: README_SURFACES.length };
}

/* ---------- self-test: node g2-readme-honesty.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0;
  const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  function defectIfVerifiedTrue(r, label) {
    const lie = !!(r && r.verified === true);
    const refused = !!(r && r.verified === false && r.refuse === true);
    console.log('OBSERVED ' + label + ' => ' + JSON.stringify({ verified: r && r.verified, refuse: r && r.refuse, reason: r && r.reason }) + (lie ? '  DEFECT verified:true' : '  REFUSE'));
    if (lie) {
      fail++;
      console.error('DEFECT: ' + label + ' painted falcon_verify-accepted / { verified: true } from heuristic-only');
      return;
    }
    ok(refused, label + ' refuses (verified:false, not a falcon_verify result)');
  }

  // FAIL-TEST: named gate must FAIL the npm README lie
  defectIfVerifiedTrue(
    gateReadmeFalconClaim({ paintedClaim: '{ verified: true }', heuristicOnly: true, falconVerifyRan: false, opcodeRan: false, wasmRan: false }),
    'FAIL-TEST gateReadmeFalconClaim(heuristic-only, paint={ verified: true })'
  );
  defectIfVerifiedTrue(
    gateReadmeFalconClaim({
      paintedClaim: "{ verified: true, signature: { headerHex:'0xba', totalLen:1236, deterministic:true, fmt:'compressed', logn:10 } }",
      heuristicOnly: true, falconVerifyRan: false, opcodeRan: false, wasmRan: false,
    }),
    'FAIL-TEST gateReadmeFalconClaim(heuristic-only, paint=verifyOnChain verified:true + headerHex 0xba)'
  );
  defectIfVerifiedTrue(
    gateReadmeFalconClaim({
      paintedClaim: 'i_ box as proof that falcon_verify accepted the signature',
      heuristicOnly: true, falconVerifyRan: false, opcodeRan: false, wasmRan: false,
    }),
    'FAIL-TEST gateReadmeFalconClaim(heuristic-only, paint=i_ box as falcon_verify proof)'
  );

  // FAIL-TEST: inventing a chain result is refused (this gate never runs an indexer as proof)
  defectIfVerifiedTrue(
    gateReadmeFalconClaim({ paintedClaim: '{ verified: true }', inventedChainResult: true, testnetResult: true }),
    'FAIL-TEST gateReadmeFalconClaim(invented TestNet result)'
  );

  // TOTAL / fail-closed
  ok(gateReadmeFalconClaim(null).verified === false, 'TOTAL: null -> verified false');
  ok(gateReadmeFalconClaim(undefined).verified === false, 'TOTAL: undefined -> verified false');
  ok(gateReadmeFalconClaim('verified').verified === false, 'TOTAL: string -> verified false');
  ok(gateReadmeFalconClaim({}).verified === false, 'TOTAL: {} -> verified false (never an opcode pass)');
  ok(gateReadmeFalconClaim([]).verified === false, 'TOTAL: [] -> verified false');
  ok(gateReadmeFalconClaim(42).verified === false, 'TOTAL: number -> verified false');

  // Honest copy is allowed as docs but is NOT verified:true
  const honest = gateReadmeFalconClaim({
    paintedClaim: 'heuristicMatch only; this function does not run falcon_verify',
    heuristicOnly: true, falconVerifyRan: false, opcodeRan: false, wasmRan: false,
  });
  console.log('OBSERVED honest heuristic copy => ' + JSON.stringify({ verified: honest.verified, refuse: honest.refuse, allowed: honest.allowed }) + (honest.verified === true ? '  DEFECT verified:true' : '  ALLOWED-AS-DOCS not falcon_verify'));
  ok(honest.verified === false && honest.refuse === false && honest.allowed === true,
    'honest heuristic copy is allowed as docs and is not falcon_verify-accepted');

  // Mutation restoring the current README example MUST FAIL the scanner
  const restoredExample = [
    "const { verifyOnChain } = require('@trelyan/verify-pqc');",
    "const r = await verifyOnChain('763809096'); // Algorand TestNet app",
    "// { verified: true, signature: { headerHex:'0xba', totalLen:1236, deterministic:true, fmt:'compressed', logn:10 },",
    "//   inscriptionBox: true, sigTxid: 'SQEPDOZ4…' }",
  ].join('\n');
  const mutatedExample = scanReadmePaint(restoredExample);
  console.log('OBSERVED FAIL-TEST mutation restoring README { verified: true, signature: { headerHex:\'0xba\'... => ' + JSON.stringify({ lie: mutatedExample.lie, onChainVerifiedTrue: mutatedExample.onChainVerifiedTrue, paints: mutatedExample.paints.length }) + (mutatedExample.lie ? '  CATCH' : '  DEFECT miss'));
  ok(mutatedExample.lie === true && mutatedExample.onChainVerifiedTrue === true,
    'FAIL-TEST: restoring verifyOnChain { verified: true, signature: { headerHex:\'0xba\'... FAIL the scanner');
  defectIfVerifiedTrue(
    gateReadmeFalconClaim({ heuristicOnly: true, source: restoredExample, falconVerifyRan: false, opcodeRan: false, wasmRan: false }),
    'FAIL-TEST gateReadmeFalconClaim(mutated README verifyOnChain example)'
  );

  const restoredIBox = '`verifyOnChain` trusts the single indexer you point at and reads the contract\'s write-once `i_` box as proof that\n`falcon_verify` accepted the signature; it does not re-run the opcode locally.';
  const mutatedIBox = scanReadmePaint(restoredIBox);
  console.log('OBSERVED FAIL-TEST mutation restoring i_ box as proof that falcon_verify accepted => ' + JSON.stringify({ lie: mutatedIBox.lie, iBoxAsProof: mutatedIBox.iBoxAsProof }) + (mutatedIBox.lie ? '  CATCH' : '  DEFECT miss'));
  ok(mutatedIBox.lie === true && mutatedIBox.iBoxAsProof === true,
    'FAIL-TEST: restoring "i_ box as proof that falcon_verify accepted the signature" FAIL the scanner');
  defectIfVerifiedTrue(
    gateReadmeFalconClaim({ heuristicOnly: true, source: restoredIBox, falconVerifyRan: false, opcodeRan: false, wasmRan: false }),
    'FAIL-TEST gateReadmeFalconClaim(mutated README i_ box proof sentence)'
  );

  // verifyThrondarStrong `{ verified: true }` is noble ML-DSA — not this lie
  const throndar = "const v = await verifyThrondarStrong(j.signed_tree_head);\n// { verified: true /* ← the ML-DSA-87 result, ONLY */, slhdsa: { slhPresent: true, slhValid: true }, ... }";
  ok(scanReadmePaint(throndar).lie === false,
    'verifyThrondarStrong { verified: true } comment is not this gate\'s lie (noble ML-DSA path)');

  // Shipped README surfaces must not paint the lie; missing files FAIL
  const shipped = scanShippedReadmes();
  if (!shipped.ok) {
    fail++;
    console.error('FAIL: shipped README surfaces still paint verifyOnChain as falcon_verify-accepted / { verified: true }:\n   ' + shipped.findings.map((f) => f.file + (f.reason ? ' (' + f.reason + ')' : '') + (f.paints && f.paints.length ? ' paints=' + f.paints.join('|') : '') + (f.onChainVerifiedTrue ? ' onChain-verified:true' : '') + (f.iBoxAsProof ? ' i_-box-as-proof' : '')).join('\n   '));
  } else {
    pass++;
    console.log('OBSERVED shipped README surfaces (' + shipped.scanned + ') have no verifyOnChain { verified: true } / i_ box-as-falcon_verify-proof paint  PASS');
  }

  // npm README honest copy + Throndar comment left intact
  const npmReadmePath = join(repoRoot, 'packages/verify-pqc/README.md');
  ok(existsSync(npmReadmePath), 'packages/verify-pqc/README.md exists (npm files surface)');
  if (existsSync(npmReadmePath)) {
    const npmReadme = readFileSync(npmReadmePath, 'utf8');
    ok(/heuristicMatch only;\s*this function does not run falcon_verify/i.test(npmReadme)
      || (/heuristicMatch/.test(npmReadme) && /does not run\s*`?falcon_verify/i.test(npmReadme)),
      'npm README documents heuristicMatch and that verifyOnChain does not run falcon_verify');
    ok(/verified:\s*false/.test(npmReadme), 'npm README shows verified: false for verifyOnChain');
    ok(/verifyThrondarStrong[\s\S]{0,220}verified:\s*true/.test(npmReadme),
      'verifyThrondarStrong { verified: true } comment left intact (noble ML-DSA path)');
  }

  ok(typeof gateReadmeFalconClaim === 'function' && GATE_NAME === 'gateReadmeFalconClaim', 'named gate is gateReadmeFalconClaim (G2, not gradeOf / gatePagesFalconClaim / gateAnchorHonesty)');
  ok(G2_README_DOMAIN === 'trelyan-g2-readme-honesty-v1', 'unique G2 domain string');
  ok(canon({ b: 2, a: 1 }) === '{"a":1,"b":2}', 'canon() is sorted-key type-distinct');

  console.log('g2-readme-honesty self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /g2-readme-honesty\.mjs$/.test(process.argv[1] || '')) selfTest();
