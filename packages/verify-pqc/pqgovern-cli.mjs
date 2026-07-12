/*!
 * pqgovern-cli — a CI/CD command for AI-governance admission (reference, DRAFT).
 *
 * Drop into a pipeline: `node pqgovern-cli.mjs <evidence-pack.json> <config.json>` re-derives the whole
 * governed admission from the SIGNED artifacts in the pack, under the trust anchors (pins) the CONFIG
 * supplies, and EXITS 0 (ADMIT) or 1 (BLOCK / did-not-verify) — so "ship this AI model only if its
 * governance evidence admits" becomes one gate step. (Transparency-log inclusion verification carries
 * raw Merkle bytes that don't round-trip JSON, so it stays a PROGRAMMATIC step — call pqgovern-anchor's
 * verifyAnchoredAdmission on in-memory objects; this file-based CLI covers the evidence-pack admission.)
 *
 * The config is the VERIFIER's own trust — pinned per-leg public keys (hex), suite registry, and the
 * window/version pins. The pack carries NO trust and NO verdict; the CLI recomputes everything. Gate on
 * the EXIT CODE (or the printed ADMIT/BLOCK), never on "the file parsed". Honest scope inherits every
 * governance leg's limit (see pqgovern-evidence / -policy / -anchor); not a certification of the model.
 *  Self-test: node pqgovern-cli.mjs   (no args = self-test; 2 file args = verify + exit 0/1)
 */
import { hexToBytes } from '@noble/hashes/utils.js';
import * as evidence from './pqgovern-evidence.mjs';

/** reconstruct a per-leg sealOpts {requireKinds, trusted:{alg:bytes}} from the config's hex pins. */
function sealOptsOf(pinMap, requireKinds) {
  if (!pinMap || typeof pinMap !== 'object') return undefined;
  const trusted = {};
  for (const [alg, hex] of Object.entries(pinMap)) { if (typeof hex === 'string') trusted[alg] = hexToBytes(hex); }
  return { requireKinds, trusted };
}

/** buildVerifyOpts(cfg) — the opts object for verifyEvidencePack, reconstructed from a JSON config. */
export function buildVerifyOpts(cfg = {}) {
  const rk = cfg.requireKinds;
  const pins = cfg.pins || {};
  return {
    aibomSealOpts: sealOptsOf(pins.aibom, rk), evalSealOpts: sealOptsOf(pins.eval, rk),
    traceSealOpts: sealOptsOf(pins.trace, rk), policySealOpts: sealOptsOf(pins.policy, rk),
    packSealOpts: sealOptsOf(pins.packager, rk),
    suiteRegistry: Array.isArray(cfg.suiteRegistry) ? cfg.suiteRegistry : cfg.suiteRegistry,
    loadedComponents: cfg.loadedComponents,
    atTs: cfg.atTs, minVersion: cfg.minVersion, expectedPolicyHash: cfg.expectedPolicyHash,
    requireWindow: cfg.requireWindow, requireDistinctSigners: cfg.requireDistinctSigners,
    requirePackagerSeal: cfg.requirePackagerSeal, allowUnpinnedPackager: cfg.allowUnpinnedPackager,
  };
}

/** runAdmission(pack, cfg) -> { admit, result, report, exitCode }. TOTAL, fail-closed. Gate on exitCode
 *  (0 = ADMIT). Re-derives the whole admission from the pack under the config's pins — no trust in the pack. */
export function runAdmission(pack, cfg = {}) {
  try {
    const r = evidence.verifyEvidencePack(pack, buildVerifyOpts(cfg));
    return { admit: !!r.admit, result: r, report: evidence.evidenceReport(pack, r), exitCode: r.admit ? 0 : 1 };
  } catch { return { admit: false, result: null, report: 'AI GOVERNANCE ADMISSION: BLOCK\n  ✗ exception (fail-closed)', exitCode: 1 }; }
}

async function cli(packPath, cfgPath) {
  const { readFileSync } = await import('fs');
  let pack, cfg;
  try { pack = JSON.parse(readFileSync(packPath, 'utf8')); cfg = JSON.parse(readFileSync(cfgPath, 'utf8')); }
  catch (e) { console.error('AI GOVERNANCE ADMISSION: BLOCK\n  ✗ could not read/parse inputs: ' + e.message); if (typeof process !== 'undefined' && process.exit) process.exit(1); return; }
  const out = runAdmission(pack, cfg);
  console.log(out.report);
  if (typeof process !== 'undefined' && process.exit) process.exit(out.exitCode);
}

/* ---------- self-test: node pqgovern-cli.mjs ---------- */
async function selfTest() {
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const policy = await import('./pqgovern-policy.mjs');
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { bytesToHex } = await import('@noble/hashes/utils.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  const declarant = [mk(11), mkEd(12)], evaluator = [mk(13), mkEd(14)], runner = [mk(15), mkEd(16)], owner = [mk(17), mkEd(18)];
  const hexPins = (s) => ({ 'ML-DSA-87': bytesToHex(s[0].publicKey), 'Ed25519': bytesToHex(s[1].publicKey) });
  const H = 'a'.repeat(64);
  const manifest = { components: [
    { type: 'model', name: 'acme-llm', version: '1.0', weights_sha256: H, provider: 'Acme', source_url: 'https://hf.co/acme/llm', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://hf.co/acme/llm/card' },
    { type: 'dataset', name: 'acme-corpus', hash: H, provenance: 'curated 2025', license: 'CC-BY-4.0', data_classification: 'internal', consent_mechanism: 'licensed', split: 'train' },
  ] };
  const evalRec = {
    eval_suite: { name: 'HELM-lite', version: '1.0', suite_type: pqeval.SUITE_TYPE.registered_standard, registry_ref: 'https://crfm.stanford.edu/helm', expected_metrics: ['mmlu'], expected_safety: ['jailbreak'] },
    methodology: { harness: 'lm-eval-harness', harness_version: '0.4', config_hash: 'cfg', seed_selection_method: 'fixed_standard' },
    metrics: [{ name: 'mmlu', split: 'test', value: 0.71, ci: 0.01, primary: true, n: 14000, contamination: 'checked_clean' }],
    safety: [{ category: 'jailbreak', tested: true, result: 'pass', n_cases: 200 }],
  };
  const run = { steps: [{ kind: 'prompt', actor: 'user', content: 'capital of France?' }, { kind: 'model_output', actor: 'acme-llm', model_id: 'acme-llm', content: 'Paris.', tokens: { input: 5, output: 1 } }] };
  const registryHash = pqeval.suiteHash(pqeval.normalizeEval({ eval_suite: evalRec.eval_suite }).eval_suite);
  const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: new Set([registryHash]) });
  const signedPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true } }), owner);
  const pack = evidence.buildEvidencePack({ record, signedPolicy }, { packager: 'Acme Release Eng', created_ts: 1200 });

  // the CONFIG a CI job ships: the verifier's own pins (hex) + registry + window/version, as JSON.
  const cfg = {
    requireKinds: ['lattice', 'classical'],
    pins: { aibom: hexPins(declarant), eval: hexPins(evaluator), trace: hexPins(runner), policy: hexPins(owner) },
    suiteRegistry: [registryHash], loadedComponents: manifest.components,
    atTs: 1000, minVersion: 3, requireWindow: true, requireDistinctSigners: true,
  };
  // round-trip the config + pack through JSON (as the CLI reads them from files)
  const cfgJson = JSON.parse(JSON.stringify(cfg)); const packJson = JSON.parse(JSON.stringify(pack));

  // 1. clean pack + honest config -> ADMIT, exit 0
  const g1 = runAdmission(packJson, cfgJson);
  ok(g1.admit === true && g1.exitCode === 0, 'clean pack + honest pins (from JSON config) -> ADMIT, exit 0');
  ok(/ADMISSION: ADMIT/.test(g1.report) && /A \(Bound\)/.test(g1.report), 'CLI report renders the admission + grade');

  // 2. wrong pins in config -> BLOCK, exit 1
  const badCfg = JSON.parse(JSON.stringify(cfg)); badCfg.pins.eval = hexPins([mk(99), mkEd(98)]);
  ok(runAdmission(packJson, badCfg).exitCode === 1, 'a config pinning the WRONG evaluator key -> BLOCK, exit 1');
  // 3. stale policy pin (minVersion) -> BLOCK
  const staleCfg = JSON.parse(JSON.stringify(cfg)); staleCfg.minVersion = 9;
  ok(runAdmission(packJson, staleCfg).exitCode === 1, 'minVersion pin above the policy version -> BLOCK, exit 1');
  // 4. tampered pack -> BLOCK
  const tampered = JSON.parse(JSON.stringify(pack)); tampered.record.subject = 'TRUSTED FedRAMP System';
  ok(runAdmission(tampered, cfgJson).exitCode === 1, 'a tampered pack -> BLOCK, exit 1');
  // 5. missing pins -> fail-closed BLOCK
  ok(runAdmission(packJson, { requireKinds: ['lattice', 'classical'] }).exitCode === 1, 'a config with no pins -> fail-closed BLOCK, exit 1');
  // 6. garbage -> fail-closed
  ok(runAdmission(null, cfgJson).exitCode === 1 && runAdmission(packJson, null).exitCode === 1, 'garbage inputs -> fail-closed, exit 1');

  // 7. requireWindow honored from the config; an atTs outside the policy window -> BLOCK
  const expiredCfg = JSON.parse(JSON.stringify(cfg)); expiredCfg.atTs = 9000;
  ok(runAdmission(packJson, expiredCfg).exitCode === 1, 'atTs past the policy expiry (config-driven window) -> BLOCK, exit 1');

  console.log('pqgovern-cli self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /pqgovern-cli\.mjs$/.test(process.argv[1] || '')) {
  if (process.argv.length >= 4) cli(process.argv[2], process.argv[3]);
  else selfTest();
}
