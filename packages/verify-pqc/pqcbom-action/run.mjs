/*! TRELYAN Quantum-Safe Scorecard — GitHub Action runner. Scans the repo, emits a CycloneDX CBOM + grade,
 *  writes the shields badge endpoint, sets outputs/step-summary, and fails the build per policy. */
import { scanDirectory, toCycloneDX, toSARIF } from '../pqcbom.mjs';
import { scorecardBadge, policyGate } from '../pqcbom-server.mjs';
import { writeFileSync, appendFileSync } from 'fs';

const path = process.env.INPUT_PATH || '.';
const failOn = (process.env['INPUT_FAIL-ON'] ?? 'broken-classical').split(',').map((s) => s.trim()).filter(Boolean);
const minGrade = (process.env['INPUT_MIN-GRADE'] || '').trim();

// CI gate grades on CODE occurrences (a comment that mentions "MD5" should not fail a build); the full report still
// lists comment/doc mentions as 'informational'. (A one-time assessment uses the conservative total-count default.)
const r = await scanDirectory(path, { gradeContext: 'code' });
writeFileSync('cbom.cdx.json', JSON.stringify(toCycloneDX(r), null, 2));
writeFileSync('quantum-safe-badge.json', JSON.stringify(scorecardBadge(r.grade)));
// SARIF for GitHub code-scanning — findings appear in the Security tab + as inline PR annotations (paths repo-relative)
writeFileSync('pqcbom.sarif', JSON.stringify(toSARIF(r, { baseDir: path }), null, 2));

if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `grade=${r.grade.letter}\nscore=${r.grade.score}\nsarif-file=pqcbom.sarif\ncbom-file=cbom.cdx.json\n`);
const bc = r.summary.by_confidence || { likely: 0, lead_to_verify: 0, informational: 0 };
const summary = `## 🛡️ Quantum-Safe Scorecard: ${r.grade.letter} (${r.grade.score}/100)\n\n**${r.grade.label}** — ${r.summary.files_scanned} files, ${r.summary.distinct_algorithms} algorithms\n\n| risk | count |\n|---|---|\n| ⛔ broken-classical | ${r.summary.broken_classical} |\n| 🔴 quantum-broken | ${r.summary.quantum_broken} |\n| 🟡 quantum-weakened | ${r.summary.quantum_weakened} |\n| 🔵 classical (hybrid-ok) | ${r.summary.classical_hybrid_ok} |\n| 🟢 quantum-safe | ${r.summary.quantum_safe} |\n\n**Confidence** (tool-derived): 🟢 likely (declared dependency) ${bc.likely} · 🟡 lead-to-verify (in code) ${bc.lead_to_verify} · ⚪ informational (comment/doc) ${bc.informational}${r.summary.suppressed ? `\n\n_${r.summary.suppressed} occurrence(s) suppressed via inline \`pqcbom-ignore\` / \`.pqcbomignore\` (accepted, not graded)._` : ''}\n\nTwo-layer scan (inline patterns + dependency manifests). Findings are leads to verify, not a complete inventory. Artifacts: \`cbom.cdx.json\` (CycloneDX CBOM), \`pqcbom.sarif\` (upload to GitHub code-scanning to see findings in the Security tab).\n`;
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
console.log(summary);

if (failOn.length || minGrade) {
  const gate = policyGate(r, { failOn, minGrade: minGrade || undefined });
  if (!gate.pass) { console.error('::error::Quantum-Safe gate failed: ' + gate.violations.join('; ')); process.exit(1); }
  console.log('Quantum-Safe gate: PASS');
}
