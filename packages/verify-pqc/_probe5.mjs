import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { assessCompliance, signComplianceReport, verifyComplianceReport } from './pqcompliance.mjs';
import { scanFiles } from './pqcbom.mjs';

const signer = ml_dsa87.keygen(new Uint8Array(32).fill(63));
const vuln = scanFiles([{ name: 'legacy.js', text: 'RSA.generate(2048); MD5; AES-128;' }]);
const r = assessCompliance(vuln, { subject: 'acme', generated_ts: 1 });
const signed = signComplianceReport(r, signer.secretKey, signer.publicKey);
console.log('real grade:', signed.grade.letter, signed.grade.score);

// Attempt: forge ONLY grade.score (letter stays F) to look like a different score. Score in core -> sig breaks.
const f = JSON.parse(JSON.stringify(signed)); f.grade.score = 100;
console.log('forge score only (letter F kept):', verifyComplianceReport(f, signer.publicKey).verified, '(expect false: score in signed core)');

// Attempt: forge grade.letter only -> caught by gradeOk AND signature
const f2 = JSON.parse(JSON.stringify(signed)); f2.grade.letter = 'A';
console.log('forge letter only:', verifyComplianceReport(f2, signer.publicKey).verified, '(expect false)');

// Confirm pqcbom-report ALSO binds score (it checks score explicitly): already covered. 
// Test the OPPOSITE robustness: a legit report with score present but pqcompliance never recomputes it - is there
// ANY accepted state where letter matches but score is wrong? Only if score in core differs from signed... impossible.
