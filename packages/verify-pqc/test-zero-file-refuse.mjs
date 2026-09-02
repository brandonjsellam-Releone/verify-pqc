/*!
 * test-zero-file-refuse — observational lock: gradeOf + GitHub Action + CLI
 * MUST FAIL (refuse / ungraded) on files_scanned===0 or an all-zero summary.
 *
 * A result of A/100 on a zero-file / empty scan is a DEFECT — this file exits 1.
 * Aligns Action with CLI (both exit 2, neither emits a readiness letter).
 *
 * Run: node test-zero-file-refuse.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gradeOf, scanFiles } from './pqcbom.mjs';

const here = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

function defectIfA100(g, label) {
  const isA100 = g && (g.letter === 'A' || g.score === 100);
  const refused = !!(g && g.ungraded === true && g.letter !== 'A' && g.score !== 100);
  console.log('OBSERVED ' + label + ' => ' + JSON.stringify({ letter: g && g.letter, score: g && g.score, ungraded: g && g.ungraded }) + (isA100 ? '  DEFECT A/100' : '  REFUSE/ungraded'));
  if (isA100) {
    fail++;
    console.error('DEFECT: ' + label + ' still grades A/100 on a zero-file / all-zero scan');
    return;
  }
  ok(refused, label + ' refuses (ungraded, not A/100)');
}

defectIfA100(gradeOf({ files_scanned: 0, broken_classical: 0, quantum_broken: 0, quantum_weakened: 0, classical_hybrid_ok: 0, quantum_safe: 0 }), 'FAIL-TEST gradeOf(files_scanned===0)');
defectIfA100(gradeOf({}), 'FAIL-TEST gradeOf({})');
defectIfA100(gradeOf({ broken_classical: 0, quantum_broken: 0, quantum_weakened: 0, classical_hybrid_ok: 0, quantum_safe: 0 }), 'FAIL-TEST gradeOf(all-zero tallies, no files_scanned)');
const emptyScan = scanFiles([]);
ok(emptyScan.summary.files_scanned === 0, 'scanFiles([]) files_scanned===0');
defectIfA100(emptyScan.grade, 'FAIL-TEST scanFiles([])');

function spawn(bin, args, envExtra) {
  try {
    const out = execFileSync('node', [join(here, bin), ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...envExtra },
    });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status ?? 1, out: (e.stdout || '') + (e.stderr || '') };
  }
}

const work = mkdtempSync(join(tmpdir(), 'pqcbom-zero-'));
try {
  const empty = join(work, 'empty');
  mkdirSync(empty);

  const cli = spawn('pqcbom-cli.mjs', [empty]);
  console.log('OBSERVED CLI empty-dir exit=' + cli.code + (cli.code === 2 ? '  REFUSE' : '  DEFECT'));
  ok(cli.code === 2, 'CLI empty dir exits 2 (refuse)');
  ok(!/Scorecard: A/.test(cli.out) && !/\bA\b.*100/.test(cli.out), 'CLI empty dir emits no A/100');

  const act = spawn('pqcbom-action/run.mjs', [], { INPUT_PATH: empty, 'INPUT_FAIL-ON': '' });
  console.log('OBSERVED Action empty-dir exit=' + act.code + (act.code === 2 ? '  REFUSE' : '  DEFECT'));
  ok(act.code === 2, 'Action empty dir exits 2 (aligned with CLI)');
  ok(!/Scorecard: A/.test(act.out) && !/grade=A/.test(act.out) && !/\(100\/100\)/.test(act.out), 'Action empty dir emits no A/100');
  ok(/no readiness grade emitted/.test(act.out) && /no readiness grade emitted/.test(cli.out), 'Action refuse message aligns with CLI');

  const missing = spawn('pqcbom-action/run.mjs', [], { INPUT_PATH: join(work, 'no-such-dir'), 'INPUT_FAIL-ON': '' });
  console.log('OBSERVED Action missing-path exit=' + missing.code + (missing.code === 2 ? '  REFUSE' : '  DEFECT'));
  ok(missing.code === 2, 'Action missing path exits 2 (aligned with CLI)');
  ok(!/Scorecard: A/.test(missing.out), 'Action missing path emits no grade A');
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log('test-zero-file-refuse: ' + pass + ' pass, ' + fail + ' fail');
if (fail) process.exit(1);
