/*!
 * test-all — runs every PQ SDK module self-test and aggregates. Run: node test-all.mjs
 */
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const here = dirname(fileURLToPath(import.meta.url));
const mods = ['pqef.mjs', 'polarseek.mjs', 'pqsign.mjs', 'pqtransport.mjs', 'pqanswer.mjs', 'pqcouncil.mjs', 'pqguard.mjs', 'pqinduct.mjs', 'pqmoa.mjs', 'pqclaimgate.mjs', 'pqverify.mjs', 'pqratchet.mjs', 'pqratchet-he.mjs', 'pqindex.mjs', 'pqassistant.mjs', 'pqcbom.mjs', 'pqcbom-server.mjs', 'pqgateway.mjs', 'fips-conformance.mjs', 'kat-conformance.mjs', 'pqtsa.mjs', 'pqgateway-session.mjs', 'pqkt.mjs', 'pqcbom-report.mjs', 'pqverify-api.mjs', 'pqpki.mjs', 'pqvault.mjs', 'pqcompliance.mjs', 'pqx3dh.mjs', 'pqmarket.mjs', 'spine-vectors.mjs', 'vectors-crosscheck.mjs', 'witness-service.mjs', 'fuzz-robustness.mjs', 'tamper-binding.mjs', 'domain-separation.mjs', 'canon-determinism.mjs', 'assurance-properties.mjs', 'accuracy-benchmark.mjs', 'pqseal.mjs', 'pqattest.mjs'];
let failed = 0;
for (const m of mods) {
  try {
    const out = execSync('node ' + m, { cwd: here }).toString().trim();
    console.log('✓ ' + out);
  } catch (e) {
    failed++;
    console.error('✗ ' + m + ' FAILED\n' + (e.stdout ? e.stdout.toString() : '') + (e.stderr ? e.stderr.toString() : ''));
  }
}
// also smoke-test the unified SDK surface loads
try {
  const sdk = await import('./sdk.mjs');
  const haveAll = sdk.pqef && sdk.polarseek && sdk.pqsign && sdk.pqtransport && sdk.pqanswer && sdk.pqcouncil && sdk.pqguard && sdk.pqinduct && sdk.pqmoa && sdk.pqclaimgate && sdk.pqverify && sdk.pqratchet && sdk.pqratchetHE && sdk.pqindex && sdk.pqassistant && sdk.pqcbom && sdk.pqgateway && sdk.pqgatewaySession && sdk.pqtsa && sdk.pqkt && sdk.pqseal && sdk.pqattest && sdk.verifyPQC && sdk.SDK_VERSION;
  console.log(haveAll ? '✓ sdk.mjs surface loads (core exports incl. pqseal + pqattest downgrade-detecting attestation) v' + sdk.SDK_VERSION : '✗ sdk.mjs missing exports');
  if (!haveAll) failed++;
} catch (e) { failed++; console.error('✗ sdk.mjs load failed: ' + e.message); }

console.log('\n=== PQ SDK: ' + (failed ? failed + ' module(s) FAILED' : 'ALL MODULES PASS') + ' ===');
if (typeof process !== 'undefined' && process.exit) process.exit(failed ? 1 : 0);
