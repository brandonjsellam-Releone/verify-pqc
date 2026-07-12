/*!
 * test-cli-guards — regression lock for the pqcbom-cli false-all-clear hazard.
 *
 * A trust tool must NEVER emit a grade-A "post-quantum ready" for a scan that
 * examined nothing. Two ways that used to happen, both now fail closed (exit 2):
 *   1. a non-existent / non-directory path (e.g. the common `pqcbom scan .`
 *      mistake, where "scan" is read as the path — there is no scan subcommand);
 *   2. a valid directory with zero scannable files.
 * And the correct path must still succeed (exit 0) and detect real crypto.
 *
 * Spawns the real CLI (execFileSync) in a temp workspace. Run: node test-cli-guards.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, 'pqcbom-cli.mjs');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

// run the CLI in `cwd`; return { code, out }
function runCli(argsArr, cwd) {
  try {
    const out = execFileSync('node', [CLI, ...argsArr], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status ?? 1, out: (e.stdout || '') + (e.stderr || '') };
  }
}

const work = mkdtempSync(join(tmpdir(), 'pqcbom-cli-'));
try {
  // 1. non-existent path → exit 2, no grade emitted
  const bad = runCli(['this-path-does-not-exist'], work);
  ok(bad.code === 2, 'non-existent path exits 2');
  ok(!/Scorecard: A/.test(bad.out), 'non-existent path emits NO grade-A');

  // 1b. the classic `pqcbom scan .` mistake — "scan" read as a (non-existent) path
  const scanMistake = runCli(['scan', '.'], work);
  ok(scanMistake.code === 2, "`pqcbom scan .` (no such subcommand) exits 2, not a false all-clear");

  // 2. valid but EMPTY directory → 0 files → exit 2, no grade
  const empty = join(work, 'empty'); mkdirSync(empty);
  const emptyRun = runCli([empty], work);
  ok(emptyRun.code === 2, 'empty directory (0 files) exits 2');
  ok(!/Scorecard: A/.test(emptyRun.out), 'empty directory emits NO grade-A all-clear');

  // 3. real source with broken crypto → exit 0, detects it, grade is NOT A
  const src = join(work, 'src'); mkdirSync(src);
  writeFileSync(join(src, 'a.js'), 'import crypto from "crypto";\nconst k=crypto.generateKeyPairSync("rsa",{modulusLength:2048});\nconst h=crypto.createHash("md5");\n');
  const good = runCli([src], work);
  ok(good.code === 0, 'valid dir with source scans successfully (exit 0)');
  ok(/files/.test(good.out) && !/0 files/.test(good.out), 'real source: >0 files scanned');
  ok(!/Scorecard: A/.test(good.out), 'source with RSA/MD5 is NOT graded A');
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(`\ntest-cli-guards: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
