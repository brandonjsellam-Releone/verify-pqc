/*!
 * pqgovern-fulfill — turnkey AI-Governance Evidence Pack DELIVERABLE producer (reference, DRAFT).
 *
 * The SDK-side complement to pqgovern-cli (which VERIFIES/admits a pack): this PRODUCES the customer-facing
 * deliverable from a signed governance record + signed policy. It builds the Evidence Pack, SELF-VERIFIES it
 * under the producer's OWN pins (FAIL CLOSED — never ship a pack that doesn't re-derive to ADMIT), and emits a
 * deliverable bundle: the signed pack + REPORT.md (auditor-facing) + VERIFY.md (how the customer re-derives the
 * verdict OFFLINE under those same public pins with pqgovern-cli). A fulfillment operator (or the jarvis-web
 * order-gated wrapper) runs this to turn a paid AI-governance order into the signed, independently-verifiable
 * artifact — mirroring pqevidence-cli's `pack` for the PQC-migration Evidence Pack.
 *
 * HONEST SCOPE (claim-hygiene LAW): produces + self-verifies a SELF-ATTESTED evidence pack — not a certification,
 * not an audit opinion, not a guarantee of quantum safety. The pack carries NO verdict; the customer re-derives it
 * under the PUBLIC pins in the config. Signer keys are the operator's (never in the repo). The pins are public keys.
 * CLI:  node pqgovern-fulfill.mjs <record.json> <signed-policy.json> <config.json> --out <dir> [--org NAME] [--order ID]
 * Self-test: node pqgovern-fulfill.mjs   (no args = self-test; produce is PURE — the self-test writes NO files)
 */
import * as evidence from './pqgovern-evidence.mjs';
import { buildVerifyOpts } from './pqgovern-cli.mjs';

const DISCLAIMER =
  'Signed, self-attested AI-governance evidence produced with the TRELYAN verify-pqc toolchain. This is NOT a\n' +
  'certification, NOT an audit opinion, NOT a conformity assessment, NOT a legal-compliance certification, and NOT a\n' +
  'guarantee of quantum safety or model safety. It proves WHO signed WHAT (an AI Bill of Materials, an evaluation, an\n' +
  'execution trace) and that a signed policy admitted the model under the pinned owner keys — it does not attest the\n' +
  'model is adequate, safe, or compliant. Supports (does not constitute) NIST AI RMF / EU AI Act preparation; not\n' +
  'legal or compliance advice.';

/** governanceReport(pack, decision, meta) — the auditor-facing REPORT.md (wraps evidenceReport with a header + the
 *  honest disclaimer). meta = { org?, order_id?, produced_ts? }. */
export function governanceReport(pack, decision, meta = {}) {
  const head = [
    '# AI-Governance Evidence Pack',
    '',
    meta.org ? `**Prepared for:** ${String(meta.org)}` : null,
    meta.order_id ? `**Order:** ${String(meta.order_id)}` : null,
    `**Verdict:** ${decision && decision.admit ? 'ADMIT' : 'BLOCK'} — re-derived under the verifier's pinned keys (the pack carries no verdict).`,
    '',
  ].filter((x) => x !== null).join('\n');
  const body = evidence.evidenceReport(pack, decision);
  return head + body + '\n\n---\n' + DISCLAIMER + '\nTRELYAN Inc.\n';
}

/** verifyInstructions(meta) — the VERIFY.md the customer follows to re-derive the verdict OFFLINE. */
export function verifyInstructions(meta = {}) {
  return `# Verifying your AI-Governance Evidence Pack (offline)

Your pack carries NO verdict — you re-derive it yourself under the PUBLIC pinned keys in \`config.json\`
(the signing parties' public keys; safe to publish). Any alteration to a signed leg, the policy, or the
cross-binding invalidates a signature and the pack BLOCKS.

    # clone github.com/brandonjsellam-Releone/verify-pqc  (or npm i -g @trelyan/verify-pqc)
    node pqgovern-cli.mjs evidence-pack.json config.json     # exit 0 = ADMIT, 1 = BLOCK

**IMPORTANT — confirm the pins.** ADMIT proves the pack is internally consistent with the PUBLIC keys in
\`config.json\`; it does NOT prove those keys belong to the right parties. Before you trust the verdict,
confirm each pin matches the expected signer's *independently published* key (declarant / evaluator / runner /
compliance owner) out of band. Optionally, transparency-log inclusion (if the admission was anchored) verifies
programmatically via \`pqgovern-anchor\` — a separate step this base pack does not require.

${meta.order_id ? `Order: ${String(meta.order_id)} · ` : ''}${DISCLAIMER}
`;
}

/** produceDeliverable({ record, signedPolicy }, cfg, opts) -> { ok, why?, pack, decision, report, verifyMd }.
 *  PURE (no filesystem). Builds the pack, SELF-VERIFIES under cfg's pins, and FAILS CLOSED (ok:false) unless the
 *  pack re-derives to ADMIT — an operator must never ship a pack that doesn't admit under its own trust anchors.
 *  cfg = the pqgovern-cli config shape (pins/requireKinds/suiteRegistry/loadedComponents/window/version pins).
 *  opts = { packager?, packSigners?, created_ts?, org?, order_id? }. */
export function produceDeliverable(input, cfg = {}, opts = {}) {
  try {
    const { record, signedPolicy } = input || {};   // guard null (a destructuring default only catches undefined)
    if (!record || !signedPolicy) return { ok: false, why: 'record and signedPolicy are required', pack: null, decision: null };
    const pack = evidence.buildEvidencePack({ record, signedPolicy }, { packager: opts.packager, packSigners: opts.packSigners, created_ts: opts.created_ts });
    const decision = evidence.verifyEvidencePack(pack, buildVerifyOpts(cfg));
    // SHIP GATE (council CRITICAL, defense-in-depth for a paid deliverable): admit alone is the verdict by design, but
    // a money-path producer must ALSO require the cryptographic integrity flags — never ship a pack unless it re-derives
    // to ADMIT *and* every leg verified. Fail closed on any of the three.
    if (!decision || decision.admit !== true || decision.integrityOk !== true || decision.artifactsVerified !== true) {
      return { ok: false, why: 'self-verify did not fully pass (admit ∧ integrityOk ∧ artifactsVerified) under the config pins — refusing to ship', pack, decision: decision || null };
    }
    return { ok: true, pack, decision, report: governanceReport(pack, decision, opts), verifyMd: verifyInstructions(opts) };
  } catch (e) { return { ok: false, why: 'exception (fail-closed): ' + ((e && e.message) || e), pack: null, decision: null }; }
}

/* ---------- CLI ---------- */
async function cli(recordPath, policyPath, cfgPath, outDir, org, orderId, force) {
  const { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } = await import('fs');
  const path = await import('path');
  let record, signedPolicy, cfg;
  try {
    record = JSON.parse(readFileSync(recordPath, 'utf8'));
    signedPolicy = JSON.parse(readFileSync(policyPath, 'utf8'));
    cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
  } catch (e) { console.error('FULFILL: could not read/parse inputs: ' + e.message); if (process.exit) process.exit(1); return; }
  const out = produceDeliverable({ record, signedPolicy }, cfg, { org, order_id: orderId, packager: org || 'TRELYAN Inc.', created_ts: cfg.atTs });
  if (!out.ok) { console.error('FULFILL: ' + out.why + ' — NO deliverable written (fail closed).'); if (process.exit) process.exit(1); return; }
  const dir = path.resolve(outDir || '.fulfillment-governance');
  // don't silently clobber a prior order's deliverable (council/operator-safety): refuse a non-empty dir w/o --force.
  if (existsSync(dir)) {
    if (readdirSync(dir).length && !force) { console.error(`FULFILL: output dir is not empty: ${dir} — refusing to overwrite a prior deliverable (pass --force to override).`); if (process.exit) process.exit(1); return; }
  } else mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, 'evidence-pack.json'), JSON.stringify(out.pack, null, 2));
  writeFileSync(path.join(dir, 'config.json'), JSON.stringify(cfg, null, 2));
  writeFileSync(path.join(dir, 'REPORT.md'), out.report);
  writeFileSync(path.join(dir, 'VERIFY.md'), out.verifyMd);
  console.log(`FULFILL: deliverable written to ${dir}\n  evidence-pack.json · config.json · REPORT.md · VERIFY.md\n  Verdict: ADMIT (self-verified). Review REPORT.md before sending.`);
}

/* ---------- self-test: node pqgovern-fulfill.mjs ---------- */
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
  const cfg = {
    requireKinds: ['lattice', 'classical'],
    pins: { aibom: hexPins(declarant), eval: hexPins(evaluator), trace: hexPins(runner), policy: hexPins(owner) },
    suiteRegistry: [registryHash], loadedComponents: manifest.components,
    atTs: 1000, minVersion: 3, requireWindow: true, requireDistinctSigners: true,
  };
  // round-trip record/policy/cfg through JSON, as the CLI reads them from files.
  const recordJ = JSON.parse(JSON.stringify(record)), policyJ = JSON.parse(JSON.stringify(signedPolicy)), cfgJ = JSON.parse(JSON.stringify(cfg));

  // 1. HAPPY PATH — produce a deliverable that self-verifies to ADMIT (PURE — no files written)
  const d = produceDeliverable({ record: recordJ, signedPolicy: policyJ }, cfgJ, { org: 'Acme Inc', order_id: 'ord_001' });
  ok(d.ok === true && d.decision.admit === true, 'produceDeliverable: builds a pack that SELF-VERIFIES to ADMIT under the config pins');
  ok(/ADMIT/.test(d.report) && /A \(Bound\)/.test(d.report) && /Acme Inc/.test(d.report) && /ord_001/.test(d.report), 'REPORT.md carries the ADMIT verdict, the AIBOM grade, the org, and the order id');
  ok(/NOT a\ncertification/.test(d.report) && /pqgovern-cli\.mjs evidence-pack\.json config\.json/.test(d.verifyMd), 'the honest disclaimer + the offline re-verify command are in the deliverable');

  // 2. the produced pack re-verifies through the CLI path too (pack carries no verdict; re-derived under the pins)
  const { runAdmission } = await import('./pqgovern-cli.mjs');
  ok(runAdmission(JSON.parse(JSON.stringify(d.pack)), cfgJ).exitCode === 0, 'the produced pack round-trips JSON and ADMITS through pqgovern-cli (exit 0)');

  // 3. FAIL CLOSED — a config pinning the WRONG owner key must NOT ADMIT -> no deliverable produced
  const badCfg = JSON.parse(JSON.stringify(cfg)); badCfg.pins.policy = hexPins([mk(88), mkEd(89)]);
  const dBad = produceDeliverable({ record: recordJ, signedPolicy: policyJ }, badCfg, {});
  ok(dBad.ok === false && !dBad.report, 'FAIL CLOSED: a pack that does not self-verify to ADMIT is REFUSED (no deliverable)');

  // 4. FAIL CLOSED — a tampered record (spoofed subject) is refused
  const spoof = JSON.parse(JSON.stringify(record)); spoof.subject = 'TRUSTED FedRAMP System';
  ok(produceDeliverable({ record: spoof, signedPolicy: policyJ }, cfgJ, {}).ok === false, 'FAIL CLOSED: a tampered record (attribution spoof) is refused');

  // 5. missing inputs / garbage -> fail-closed
  ok(produceDeliverable({}, cfgJ).ok === false && produceDeliverable(null, cfgJ).ok === false && produceDeliverable({ record: recordJ, signedPolicy: policyJ }, {}).ok === false, 'missing record/policy or empty (pinless) config -> fail-closed, no deliverable');

  // 6. NO-SECRET lock (council): a pack built WITH a packager seal embeds signatures + PUBLIC keys only — the
  //    packager's SECRET key must NEVER appear in the shipped pack / report / VERIFY.md. (The packager must be PINNED
  //    in the config, else the stricter ship gate correctly refuses a sealed-but-unverifiable pack — see test 6b.)
  const packager = [mk(31), mkEd(32)];
  const sealedCfg = JSON.parse(JSON.stringify(cfg)); sealedCfg.pins.packager = hexPins(packager);
  const dSealed = produceDeliverable({ record: recordJ, signedPolicy: policyJ }, sealedCfg, { packager: 'Acme Release Eng', packSigners: packager, order_id: 'ord_002' });
  const shipped = JSON.stringify(dSealed.pack) + (dSealed.report || '') + (dSealed.verifyMd || '');
  ok(dSealed.ok === true && !shipped.includes(bytesToHex(packager[0].secretKey)) && !shipped.includes(bytesToHex(packager[1].secretKey)), 'NO-SECRET: a packager-sealed deliverable leaks NO packager secret key (public keys + signatures only)');
  // 6b. the stricter ship gate: a packager seal that the config does NOT pin -> artifactsVerified false -> REFUSED.
  ok(produceDeliverable({ record: recordJ, signedPolicy: policyJ }, cfgJ, { packager: 'Acme', packSigners: packager }).ok === false, 'ship gate: a sealed pack whose packager the config does not pin -> REFUSED (admit ∧ integrityOk ∧ artifactsVerified)');

  console.log('pqgovern-fulfill self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /pqgovern-fulfill\.mjs$/.test(process.argv[1] || '')) {
  const a = process.argv.slice(2);
  const flag = (k) => { const i = a.indexOf('--' + k); return i >= 0 && i + 1 < a.length ? a[i + 1] : null; };
  const pos = a.filter((x) => !x.startsWith('--') && a[a.indexOf(x) - 1] !== '--out' && a[a.indexOf(x) - 1] !== '--org' && a[a.indexOf(x) - 1] !== '--order');
  if (pos.length >= 3) cli(pos[0], pos[1], pos[2], flag('out'), flag('org'), flag('order'), a.includes('--force'));
  else selfTest();
}
