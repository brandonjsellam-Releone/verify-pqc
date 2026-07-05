/*! pqcbom-action/action-lib.mjs — the ZERO-DEPENDENCY subset of pqcbom-server (scorecardBadge + policyGate).
 *  A `node20` GitHub Action runs run.mjs directly with NO `npm install`, so the action must not import anything
 *  that pulls node_modules (pqcbom-server.mjs pulls @noble via the Evidence Pack). These two functions are pure.
 *  Source of truth: ../pqcbom-server.mjs — keep byte-equivalent if you change the canonical logic. */

const GRADE_COLOR = { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' };
const gradeRank = (g) => ({ F: 0, D: 1, C: 2, B: 3, A: 4 }[g] ?? 0);
const RISK_CLASSES = new Set(['broken-classical', 'quantum-broken', 'quantum-weakened', 'classical-hybrid-ok', 'quantum-safe']);
const VALID_GRADES = new Set(['A', 'B', 'C', 'D', 'F']);

// shields.io endpoint schema — README badge via https://img.shields.io/endpoint?url=<this JSON>. JSON only, no SVG.
export function scorecardBadge(grade) {
  return { schemaVersion: 1, label: 'PQ Readiness', message: grade.letter + ' (' + grade.score + ')', color: GRADE_COLOR[grade.letter] || 'lightgrey' };
}

// CI policy gate: fail on banned risk classes and/or below a minimum grade. Fails CLOSED on a typo'd config
// (an unknown risk class or invalid min-grade is a violation, not a silent pass).
export function policyGate(report, policy = {}) {
  const failOn = policy.failOn || ['broken-classical'];
  const violations = [], configErrors = [];
  for (const risk of failOn) {
    if (!RISK_CLASSES.has(risk)) { configErrors.push('unknown fail-on risk class: "' + risk + '"'); continue; }
    const n = report.summary[risk.replace(/-/g, '_')] || 0;
    if (n > 0) violations.push(risk + ' x' + n);
  }
  if (policy.minGrade) {
    if (!VALID_GRADES.has(String(policy.minGrade).toUpperCase())) configErrors.push('invalid min-grade: "' + policy.minGrade + '" (expected A–F)');
    else if (gradeRank(report.grade.letter) < gradeRank(String(policy.minGrade).toUpperCase())) violations.push('grade ' + report.grade.letter + ' < min ' + policy.minGrade);
  }
  const all = configErrors.concat(violations); // misconfiguration fails the gate, with a clear message (not a silent pass)
  return { pass: all.length === 0, violations: all, configErrors };
}
