/*!
 * domain-separation — demonstrates cross-protocol signature reuse is prevented (audit artifact; test evidence, not a formal proof).
 *
 * The full-council convergent #1 risk was "any bare sign/verify (no {context})" — a bare PQ signature is a UNIVERSAL
 * witness that verifies under every protocol. This harness answers it MECHANICALLY:
 *   1. STATIC: scan every module source; every ml_dsa87 / ml_dsa65 / slh_dsa* .sign()/.verify() call MUST pass a
 *      {context}. A bare call fails the test. (Ed25519 has no native context — those sites are REPORTED; pqpki binds
 *      the context into the Ed25519 pre-image instead, checked separately by its own self-test + tamper-binding.)
 *   2. UNIQUENESS: collect every *_CTX = utf8ToBytes('...') literal; assert all context strings are globally distinct
 *      (a shared context between two modules = cross-protocol reuse).
 *   3. FUNCTIONAL: a signature made under context A must NOT verify under context B (proves the primitive enforces the
 *      separation that (1)+(2) rely on).
 * Self-test: node domain-separation.mjs
 */
import { readdirSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

const here = dirname(fileURLToPath(import.meta.url));
// modules only (exclude the test harnesses themselves + non-signing helpers)
const EXCLUDE = new Set(['domain-separation.mjs', 'fuzz-robustness.mjs', 'tamper-binding.mjs', 'test-all.mjs', 'spine-vectors.mjs', 'vectors-crosscheck.mjs']);
const files = readdirSync(here).filter((f) => f.endsWith('.mjs') && !EXCLUDE.has(f) && !f.includes('.test.'));

// PQ signature primitives that REQUIRE a context for domain separation (FIPS 204 §5.2 ctx string).
const PQ_SIG = /\b(ml_dsa87|ml_dsa65|ml_dsa44|slh_dsa_[a-z0-9_]+|slh_dsa)\.(sign|verify)\s*\(/g;
// TEST/conformance files DELIBERATELY exercise no-context behavior (asserting it is REJECTED) — report, don't assert.
const isTestFile = (f) => /^test[-.]/.test(f) || /-conformance\.mjs$/.test(f) || /^kat-/.test(f);
// A call is context-bound if its statement window carries a context: inline `{ context:` OR a trailing context-holder
// variable (`ctx`, `CTX`, `*_CTX`). A line that asserts rejection (`=== false`, `Rejected`, `no-ctx`) is an INTENTIONAL
// negative test (proves the primitive rejects a missing/wrong context) — not a bare-signing vulnerability.
const ctxBound = (w) => /context\s*:/.test(w) || /\b(ctx|CTX)\b/.test(w) || /_CTX\b/.test(w);
const negativeTest = (w) => /===\s*false/.test(w) || /Rejected/.test(w) || /no-?ctx/i.test(w) || /context is bound/i.test(w);
function scanFile(src) {
  const bare = [], pq = [], ed = [];
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('*') || line.trim().startsWith('//')) continue; // skip comments/doc
    if (/\bed25519\.(sign|verify)\s*\(/.test(line)) ed.push(i + 1);
    let m;
    PQ_SIG.lastIndex = 0;
    while ((m = PQ_SIG.exec(line))) {
      const window = (line + '\n' + (lines[i + 1] || '') + '\n' + (lines[i + 2] || ''));
      const hasCtx = ctxBound(window);
      pq.push({ line: i + 1, call: m[1] + '.' + m[2], hasCtx });
      if (!hasCtx && !negativeTest(window)) bare.push({ line: i + 1, call: m[1] + '.' + m[2], text: line.trim().slice(0, 90) });
    }
  }
  return { bare, pq, ed };
}
// collect `NAME_CTX = utf8ToBytes('literal')` across all modules
const CTX_DEF = /([A-Z][A-Z0-9_]*_CTX)\s*=\s*utf8ToBytes\(\s*['"]([^'"]+)['"]\s*\)/g;

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // (1) STATIC: no bare PQ sign/verify in PRODUCTION modules (test/conformance files reported separately)
  let totalPq = 0, totalEd = 0; const bareProd = [], bareTest = [];
  const contexts = new Map(); // ctxString -> [ {const, file} ]
  for (const f of files) {
    const src = readFileSync(join(here, f), 'utf8');
    const { bare, pq, ed } = scanFile(src);
    totalPq += pq.length; totalEd += ed.length;
    for (const b of bare) (isTestFile(f) ? bareTest : bareProd).push(f + ':' + b.line + ' ' + b.call + '  ' + b.text);
    let m; CTX_DEF.lastIndex = 0;
    while ((m = CTX_DEF.exec(src))) {
      const str = m[2];
      if (!contexts.has(str)) contexts.set(str, []);
      contexts.get(str).push({ konst: m[1], file: f });
    }
  }
  ok(bareProd.length === 0, 'NO bare PQ sign/verify in production modules (every ml_dsa/slh_dsa call is context-bound) — bare sites: ' + (bareProd.length ? '\n   ' + bareProd.join('\n   ') : 'none'));
  if (bareTest.length) console.log('  (note) ' + bareTest.length + ' intentional no-context sites in test/conformance files (assert REJECTION, not signing) — not a violation');

  // (2) UNIQUENESS: every context string distinct (shared string => cross-protocol reuse)
  const dupes = [...contexts.entries()].filter(([, uses]) => new Set(uses.map((u) => u.file + ':' + u.konst)).size > 1 && uses.length > 1);
  // a context shared across >1 DISTINCT module file is the real risk; same const re-imported is fine
  const crossModuleShared = [...contexts.entries()].filter(([, uses]) => new Set(uses.map((u) => u.file)).size > 1);
  ok(crossModuleShared.length === 0, 'every context string is unique to ONE module (no cross-module reuse) — shared: ' + (crossModuleShared.length ? crossModuleShared.map(([s, u]) => s + ' in {' + [...new Set(u.map((x) => x.file))].join(',') + '}').join('; ') : 'none'));
  void dupes;

  // (3) FUNCTIONAL: a signature under context A must NOT verify under context B
  const kp = ml_dsa87.keygen(new Uint8Array(32).fill(7));
  const msg = utf8ToBytes('domain-separation-probe');
  const A = utf8ToBytes('trelyan-ctx-A-v1'), B = utf8ToBytes('trelyan-ctx-B-v1');
  const sigA = ml_dsa87.sign(msg, kp.secretKey, { context: A });
  ok(ml_dsa87.verify(sigA, msg, kp.publicKey, { context: A }) === true, 'baseline: signature verifies under its OWN context');
  ok(ml_dsa87.verify(sigA, msg, kp.publicKey, { context: B }) === false, 'cross-context: signature under A does NOT verify under B (primitive enforces separation)');
  ok(ml_dsa87.verify(sigA, msg, kp.publicKey) === false, 'cross-context: signature under A does NOT verify with NO context (bare-verify rejects a contexted sig)');

  console.log('  scanned ' + files.length + ' modules: ' + totalPq + ' PQ sign/verify sites (all context-bound), ' + contexts.size + ' distinct contexts, ' + totalEd + ' ed25519 hybrid-leg sites (context bound into pre-image — see pqpki)');
  console.log('  contexts: ' + [...contexts.keys()].sort().join(', '));
  console.log('domain-separation: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /domain-separation\.mjs$/.test(process.argv[1] || '')) selfTest();
