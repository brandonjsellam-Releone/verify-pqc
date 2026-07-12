/*!
 * test-all — runs every PQ SDK module self-test and aggregates. Run: node test-all.mjs
 */
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const here = dirname(fileURLToPath(import.meta.url));
const mods = ['pqef.mjs', 'polarseek.mjs', 'pqsign.mjs', 'pqtransport.mjs', 'pqanswer.mjs', 'pqcouncil.mjs', 'pqguard.mjs', 'pqinduct.mjs', 'pqmoa.mjs', 'pqclaimgate.mjs', 'pqverify.mjs', 'pqratchet.mjs', 'pqratchet-he.mjs', 'pqindex.mjs', 'pqassistant.mjs', 'pqcbom.mjs', 'pqcbom-server.mjs', 'pqgateway.mjs', 'fips-conformance.mjs', 'kat-conformance.mjs', 'pqtsa.mjs', 'pqgateway-session.mjs', 'pqkt.mjs', 'pqcbom-report.mjs', 'pqcbom-plan.mjs', 'pqverify-api.mjs', 'pqpki.mjs', 'pqvault.mjs', 'pqcompliance.mjs', 'pqx3dh.mjs', 'pqmarket.mjs', 'spine-vectors.mjs', 'vectors-crosscheck.mjs', 'witness-service.mjs', 'fuzz-robustness.mjs', 'tamper-binding.mjs', 'domain-separation.mjs', 'canon-determinism.mjs', 'assurance-properties.mjs', 'accuracy-benchmark.mjs', 'structural-corpus.mjs', 'pqseal.mjs', 'pqattest.mjs', 'pqredact.mjs', 'pqauditlog.mjs', 'pqanchor.mjs', 'qiv.mjs', 'qiv-pin.mjs', 'omega-gov.mjs', 'omega-bridge.mjs', 'omega.mjs', 'omega-evidence.mjs', 'omega-chain.mjs', 'omega-sentinel.mjs', 'omega-nexus.mjs', 'omega-server.mjs', 'pqmesh-server.mjs', 'pqsearch-server.mjs', 'trelyan-console.mjs', 'cross-product-e2e.mjs', 'pqtls.mjs', 'pqposture.mjs', 'pqvc.mjs', 'pqpay.mjs', 'pqfirmware.mjs', 'pqshield.mjs', 'pqcap.mjs', 'pqadmit.mjs', 'pqconsent.mjs', 'pqmonitor.mjs', 'pqgate.mjs', 'pqflow.mjs', 'pqdelegate.mjs', 'pqconsentflow.mjs', 'test-slh-pins.mjs', 'demo-gateway.mjs', 'test-cli-guards.mjs', 'api-server.mjs', 'pqtrace.mjs', 'pqaibom.mjs', 'pqai-provenance-e2e.mjs', 'pqeval.mjs', 'pqgovernance-record.mjs', 'pqgovernance-gate.mjs', 'pqgovern-policy.mjs', 'pqgovern-evidence.mjs', 'pqgovern-anchor.mjs', 'pqgovern-cli.mjs', 'pqgovern-monitor.mjs', 'pqgovern-witness.mjs', 'pqgovern-witness-service.mjs', 'pqgovern-fulfill.mjs', 'pqgovern-e2e.mjs'];   // test-slh-pins: the headline browser STH verifier (mldsa/slhdsa/verify) — array-pin rotation + foreign-key soundness + non-authoritative SLH leg. demo-gateway: fail-closed bearer auth + per-key metering wrapper — makes the demo services safe to expose AND sellable as API keys
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
  const haveAll = sdk.pqef && sdk.polarseek && sdk.pqsign && sdk.pqtransport && sdk.pqanswer && sdk.pqcouncil && sdk.pqguard && sdk.pqinduct && sdk.pqmoa && sdk.pqclaimgate && sdk.pqverify && sdk.pqratchet && sdk.pqratchetHE && sdk.pqindex && sdk.pqassistant && sdk.pqcbom && sdk.pqgateway && sdk.pqgatewaySession && sdk.pqtsa && sdk.pqkt && sdk.pqseal && sdk.pqattest && sdk.pqtrace && sdk.pqaibom && sdk.pqeval && sdk.pqgovernanceRecord && sdk.pqgovernanceGate && sdk.pqgovernPolicy && sdk.pqgovernEvidence && sdk.pqgovernAnchor && sdk.pqgovernCli && sdk.pqgovernMonitor && sdk.pqgovernWitness && sdk.pqgovernWitnessService && sdk.pqgovernFulfill && sdk.verifyPQC && sdk.SDK_VERSION;
  console.log(haveAll ? '✓ sdk.mjs surface loads (core exports incl. pqseal + pqattest downgrade-detecting attestation) v' + sdk.SDK_VERSION : '✗ sdk.mjs missing exports');
  if (!haveAll) failed++;
} catch (e) { failed++; console.error('✗ sdk.mjs load failed: ' + e.message); }

// 0-DOWNGRADE RATCHET (constant max-apex law: 0 downgrade, only upgrade). Modules may be ADDED, never silently
// removed — raise MIN_MODULES only upward when you add one. Dropping below the floor is a regression and fails CI.
const MIN_MODULES = 93;
if (mods.length < MIN_MODULES) { failed++; console.error('✗ 0-downgrade ratchet: mods.length ' + mods.length + ' < floor ' + MIN_MODULES + ' (a module was removed — only-upgrade law violated; restore it or this is a downgrade)'); }

console.log('\n=== PQ SDK: ' + (failed ? failed + ' module(s) FAILED' : 'ALL MODULES PASS') + ' ===');
if (typeof process !== 'undefined' && process.exit) process.exit(failed ? 1 : 0);
