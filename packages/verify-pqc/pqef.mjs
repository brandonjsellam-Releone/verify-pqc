/*!
 * @trelyan/verify-pqc/pqef — PQEF v0.1 reference verifier (DRAFT).
 *
 * Implements the offline verdict behaviour of TRELYAN_PQEF_SPEC_v0.1 §11:
 *   parse+canonicalize -> schema/secret-scan -> verify each declared leg (§5, dual-sign
 *   = BOTH-must-verify) -> provenance continuity walk (§7) -> unsubstantiated-FIPS flag
 *   (§4.3) -> recompute PQRS (§6) and compare to the embedded value -> emit a verdict.
 *
 * Profiles: this v0.1 reference uses the **canonical-JSON (RFC 8785 / JCS-style)** signing
 * profile (sorted keys, no whitespace) so it is dependency-free beyond @noble. The PRODUCTION
 * profile is deterministic CBOR (RFC 8949 §4.2); `statement.canonicalization` records which.
 * Both are deterministic; a verifier pins the profile per pqef_version.
 *
 * Falcon-1024 is the OPTIONAL on-chain/provenance leg ONLY (draft FIPS 206); the verdict logic
 * NEVER lets it satisfy a compliance control. ML-DSA-87 (FIPS 204) is the load-bearing leg.
 *
 * Peer deps (present in this package): @noble/post-quantum, @noble/hashes.
 * Run the self-test:  node pqef.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const te = (s) => new TextEncoder().encode(s);

// Optional legs are imported lazily so the module never hard-fails if a leg is absent.
async function loadSlh() { try { const m = await import('@noble/post-quantum/slh-dsa.js'); return m.slh_dsa_shake_256s; } catch { return null; } }
async function loadFalcon() { try { const m = await import('@noble/post-quantum/falcon.js'); return m.falcon1024; } catch { return null; } }

/* ---------- canonical JSON (JCS-style: recursively sorted keys, minimal separators) ---------- */
function canonicalize(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  throw new Error('non-canonicalizable value: ' + typeof v);
}

/* ---------- schema / secret-material guard (§4.1, §11.2) ---------- */
const SECRET_KEY_RE = /(?:^|_)(priv|private|secret|seed|mnemonic|sk)(?:$|_|key)/i;
const ALLOWED_HASHES = new Set(['SHA-384', 'SHA-512']);
function secretScan(obj, path, out) {
  if (obj && typeof obj === 'object') {
    for (const k of Object.keys(obj)) {
      if (SECRET_KEY_RE.test(k)) out.push((path ? path + '.' : '') + k);
      secretScan(obj[k], (path ? path + '.' : '') + k, out);
    }
  }
  return out;
}

// TYPED, VERSION-PINNED SCHEMA ALLOWLIST (hardening + Moonshot follow-ups). A name-blacklist misses secrets under
// innocuous keys, inside allowed VALUES, or via type-confusion. This is a fail-closed STRUCTURAL schema, pinned per
// pqef_version: each path maps key -> expected type ('string'|'number'|'boolean'|'object'|'array<object>'|
// 'array<string>', or a union array e.g. ['string','null']). Violation paths are RFC-6901 JSON Pointers. New
// pqef_versions MUST register a schema here (unknown version -> fail-closed).
const SCHEMA_V01 = {
  '': { pqef_version: 'string', statement_type: 'string', canonicalization: 'string', hash_alg: 'string', subject: 'object', collected_at: 'string', migration_state: 'object', collectors: 'array<object>', control_mappings: 'array<object>', provenance: 'object', readiness_score: 'object' },
  'subject': { org_pseudonym: 'string', estimated_assets: 'number', system: 'object', scope: 'string' },
  'subject.system': { name: 'string', boundary_id: 'string', env: 'string' },
  'migration_state': { totals: 'object', fips_module: 'object' },
  'migration_state.totals': { inventoried: 'number', assessed: 'number', planned: 'number', in_migration: 'number', hybrid_deployed: 'number', pqc_deployed: 'number', verified: 'number', exception: 'number' },
  'migration_state.fips_module': { cmvp_cert: 'string', validated: 'boolean' },
  'collectors[]': { collector_id: 'string', type: 'string' },
  'control_mappings[]': { framework: 'string', control_id: 'string', status: 'string' },
  'provenance': { steps: 'array<object>' },
  'provenance.steps[]': { step_id: 'string', action: 'string', prev: ['string', 'null'] },
  'readiness_score': { model_version: 'string', subscores: 'object', pqrs: 'number' },
  'readiness_score.subscores': { IC: 'number', MC: 'number', CA: 'number', EI_gate: 'number' },
};
export const SCHEMAS = { '0.1': SCHEMA_V01 };

// VALUE-secret detector (Moonshot fix): flag key-shaped material — PEM private-key headers, long contiguous hex
// (≥32 bytes), or long base64 — which never legitimately appears in a PQEF *statement* (keys/sigs live in envelope).
const PEM_PRIV_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const LONG_HEX_RE = /(?:0x)?[0-9a-fA-F]{64,}/;
const LONG_B64_RE = /[A-Za-z0-9+/]{48,}={0,2}/;
const valueLooksSecret = (s) => PEM_PRIV_RE.test(s) || LONG_HEX_RE.test(s) || LONG_B64_RE.test(s);
const jptr = (parent, token) => parent + '/' + String(token).replace(/~/g, '~0').replace(/\//g, '~1'); // RFC-6901
const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
function typeMatches(spec, v) {
  const specs = Array.isArray(spec) ? spec : [spec];
  const t = typeOf(v);
  return specs.some((s) => s === t || (s === 'array<object>' && t === 'array') || (s === 'array<string>' && t === 'array'));
}
function schemaScan(st, schema) {
  const bad = [];
  const scanLeafString = (v, ptr) => { if (typeof v === 'string' && valueLooksSecret(v)) bad.push('secret-value:' + ptr); };
  const walk = (obj, schemaPath, ptr) => {
    const spec = schema[schemaPath]; // { key -> type }
    for (const k of Object.keys(obj)) {
      const kp = jptr(ptr, k);
      const expected = spec ? spec[k] : undefined;
      if (spec && expected === undefined) { bad.push('unknown-key:' + kp); continue; }
      const v = obj[k];
      if (expected && !typeMatches(expected, v)) { bad.push('type-mismatch:' + kp + ' (want ' + (Array.isArray(expected) ? expected.join('|') : expected) + ', got ' + typeOf(v) + ')'); continue; }
      const child = schemaPath ? schemaPath + '.' + k : k;
      if (typeof v === 'string') scanLeafString(v, kp);
      else if (Array.isArray(v)) {
        const arrIsObj = expected === 'array<object>';
        v.forEach((it, i) => {
          const ip = jptr(kp, i);
          if (arrIsObj) { if (it && typeOf(it) === 'object') walk(it, child + '[]', ip); else bad.push('type-mismatch:' + ip + ' (want object array-item, got ' + typeOf(it) + ')'); }
          else scanLeafString(it, ip); // array<string>
        });
      } else if (v && typeOf(v) === 'object') {
        if (schema[child]) walk(v, child, kp);
        else bad.push('unexpected-nesting:' + kp); // safety net (a typed-'object' field with no child schema)
      }
      // number / boolean / null: inert
    }
  };
  if (st && typeOf(st) === 'object') walk(st, '', '');
  return bad;
}

/* ---------- PQRS (§6) ---------- */
const STATE_CREDIT = {
  inventoried: 0.05, assessed: 0.15, planned: 0.30, in_migration: 0.50,
  hybrid_deployed: 0.75, pqc_deployed: 0.90, verified: 1.00, exception: 0.40,
};
const CONFIDENCE = { automated_scanner: 0.9, kms_connector: 1.0, sbom_importer: 0.7, human_attestor: 0.5 };
const WEIGHT_TABLE_VERSION = 'pqrs-0.1';

function computePQRS(st, legsAllValid, provenanceOk, anchorsPresent) {
  const ms = st.migration_state || {}, totals = ms.totals || {};
  const total = Object.values(totals).reduce((a, b) => a + (Number(b) || 0), 0) || 1;

  // IC — inventory completeness, discounted by average collector confidence.
  const estTotal = Number((st.subject && st.subject.estimated_assets) || total);
  const conf = (st.collectors || []).map((c) => CONFIDENCE[c.type] ?? 0.6);
  const avgConf = conf.length ? conf.reduce((a, b) => a + b, 0) / conf.length : 0.6;
  const IC = Math.max(0, Math.min(1, (total / estTotal) * avgConf));

  // MC — migration coverage. v0.1 = state-count weighting (production = per-asset criticality).
  let mc = 0; for (const [stt, n] of Object.entries(totals)) mc += (STATE_CREDIT[stt] ?? 0) * (Number(n) || 0);
  const MC = Math.max(0, Math.min(1, mc / total));

  // CA — compliance alignment; capped at 0.5 without a validated FIPS module.
  const cm = st.control_mappings || [];
  const met = cm.filter((m) => m.status === 'met' || m.status === 'compensating').length;
  let CA = cm.length ? met / cm.length : 0;
  const fipsValidated = !!(ms.fips_module && ms.fips_module.validated && ms.fips_module.cmvp_cert);
  if (!fipsValidated) CA = Math.min(CA, 0.5);

  // EI_gate (graded): 0 iff a required signature fails OR provenance is broken (non-negotiable);
  // else 1.0 with anchors, 0.5 without. Honest partial disclosure is NOT punished to zero.
  const EI_gate = (!legsAllValid || !provenanceOk) ? 0 : (anchorsPresent ? 1.0 : 0.5);

  const pqrs = EI_gate * (0.20 * IC + 0.55 * MC + 0.25 * CA) * 100;
  return {
    model_version: WEIGHT_TABLE_VERSION,
    subscores: { IC: round3(IC), MC: round3(MC), CA: round3(CA), EI_gate },
    pqrs: Math.round(pqrs * 10) / 10,
  };
}
const round3 = (x) => Math.round(x * 1000) / 1000;

/* ---------- provenance continuity walk (§7) ---------- */
function provenanceContinuous(prov) {
  if (!prov || !Array.isArray(prov.steps)) return { ok: false, reason: 'no provenance.steps' };
  const ids = new Set(prov.steps.map((s) => s.step_id));
  for (const s of prov.steps) {
    if (s.prev !== null && s.prev !== undefined && !ids.has(s.prev)) return { ok: false, reason: 'broken prev link at ' + s.step_id + ' -> ' + s.prev };
  }
  const genesis = prov.steps.filter((s) => s.prev === null || s.prev === undefined);
  if (genesis.length !== 1) return { ok: false, reason: 'expected exactly one genesis step, found ' + genesis.length };
  // REACHABILITY (3rd code-security sweep): require every step reachable from the single genesis — rejects an
  // orphan/cyclic subgraph (steps whose prev links resolve to each other but never reach genesis), which the
  // per-link + single-genesis checks alone accept and would otherwise pass through to COMPLIANCE-VERIFIED.
  const children = new Map();
  for (const s of prov.steps) { if (s.prev != null) (children.get(s.prev) || children.set(s.prev, []).get(s.prev)).push(s.step_id); }
  const reached = new Set(); const stack = [genesis[0].step_id];
  while (stack.length) { const id = stack.pop(); if (reached.has(id)) continue; reached.add(id); for (const c of (children.get(id) || [])) stack.push(c); }
  if (reached.size !== prov.steps.length) return { ok: false, reason: 'provenance has orphan/cyclic steps unreachable from genesis' };
  return { ok: true, reason: 'continuous' };
}

/* ---------- the verifier (§11) ---------- */
export async function verifyPQEFBundle(bundle, opts = {}) {
  const reasons = [], errors = [], legs = [];
  try {
    if (!bundle || typeof bundle !== 'object') return fail('bundle is not an object');
    const st = bundle.statement;
    if (!st || typeof st !== 'object') return fail('missing statement');
    if (st.hash_alg && !ALLOWED_HASHES.has(st.hash_alg)) errors.push('disallowed hash_alg: ' + st.hash_alg);

    // (2) secret-material guard — VERSION-PINNED typed schema allowlist (primary, fail-closed) + name blacklist (secondary)
    const schema = SCHEMAS[st.pqef_version];
    if (!schema) errors.push('unsupported pqef_version (no pinned schema/allowlist): ' + JSON.stringify(st.pqef_version));
    else { const offSchema = schemaScan(st, schema); if (offSchema.length) errors.push('schema guard (unknown-key / type-mismatch / secret-value / unexpected-nesting): ' + offSchema.join('; ')); }
    const secrets = secretScan(st, '', []);
    if (secrets.length) errors.push('secret-looking fields present: ' + secrets.join(', '));

    // signed bytes: canonical JSON of the statement (v0.1 JSON profile)
    const signedBytes = te(canonicalize(st));

    // (3) verify each declared leg
    const sigs = (bundle.envelope && bundle.envelope.signatures) || [];
    const slh = await loadSlh(), falcon = await loadFalcon();
    // SECURITY (council fix): COMPLIANCE-VERIFIED requires the signing key to match a PINNED
    // trusted issuer supplied by the VERIFIER (opts.trustedIssuers) — never the bundle's own
    // public_key_hex / validated_module flag (those are attacker-controlled claims).
    const trusted = (opts.trustedIssuers || []).map((t) => (t.public_key_hex || '').toLowerCase());
    let mldsaValidatedValid = false, requiredAllValid = true, anyRequired = false, falconOnlyValid = false, slhValid = false;

    for (const s of sigs) {
      const required = s.required !== false; if (required) anyRequired = true;
      let valid = false, role = 'unknown', note = '';
      try {
        if (s.alg === 'ML-DSA-87') {
          role = s.validated_module ? 'compliance (FIPS 140-3 validated module)' : 'compliance-candidate (module not asserted validated)';
          const pk = hexToBytes(s.public_key_hex), sig = hexToBytes(s.sig_hex);
          const ctx = s.context ? { context: te(s.context) } : undefined;
          valid = ml_dsa87.verify(sig, signedBytes, pk, ctx);
          const issuerTrusted = trusted.includes((s.public_key_hex || '').toLowerCase());
          if (valid && !issuerTrusted) note = 'signature valid but issuer key NOT in trustedIssuers — compliance NOT granted (self-attestation)';
          if (valid && s.validated_module && issuerTrusted) mldsaValidatedValid = true;
        } else if (s.alg === 'SLH-DSA-256s') {
          role = 'diversity (hash-based)';
          if (!slh) { note = 'SLH leg not available'; }
          else { valid = slh.verify(hexToBytes(s.sig_hex), signedBytes, hexToBytes(s.public_key_hex)); slhValid = valid; }
        } else if (s.alg === 'Falcon-1024') {
          role = 'provenance/on-chain ONLY (draft FIPS 206 — never a compliance signature)';
          if (!falcon) { note = 'Falcon leg not available; provenance-only regardless'; }
          else { try { valid = falcon.verify(hexToBytes(s.sig_hex), signedBytes, hexToBytes(s.public_key_hex)); } catch { valid = false; note = 'standard falcon1024.verify did not accept (project det-wrapper sigs verify on-chain, not here)'; } }
          if (valid) falconOnlyValid = true;
        } else { note = 'unknown alg: ' + s.alg; }
      } catch (e) { note = 'verify error: ' + (e && e.message || e); valid = false; }
      if (required && !valid) requiredAllValid = false;
      legs.push({ alg: s.alg, required, valid, role, note });
    }

    // (4) provenance continuity
    const prov = provenanceContinuous(st.provenance);
    if (!prov.ok) reasons.push('provenance: ' + prov.reason);

    // (5) unsubstantiated FIPS states
    const ms = st.migration_state || {}, totals = ms.totals || {};
    const claimsDeployed = (Number(totals.pqc_deployed) || 0) + (Number(totals.verified) || 0) > 0;
    const hasCert = !!(ms.fips_module && ms.fips_module.cmvp_cert);
    const unsubstantiated = claimsDeployed && !hasCert ? ['pqc_deployed/verified state without a referenced CMVP certificate'] : [];

    // (6) PQRS recompute + compare
    const anchorsPresent = !!(bundle.anchors && Object.keys(bundle.anchors).length);
    const pqrs = computePQRS(st, requiredAllValid && anyRequired, prov.ok, anchorsPresent);
    const embedded = st.readiness_score && typeof st.readiness_score.pqrs === 'number' ? st.readiness_score.pqrs : null;
    const pqrsMatch = embedded === null ? null : Math.abs(embedded - pqrs.pqrs) < 0.15;
    if (embedded !== null && !pqrsMatch) errors.push('PQRS mismatch: embedded ' + embedded + ' vs recomputed ' + pqrs.pqrs);

    // (3/§5) verdict
    let verdict;
    if (errors.length || (anyRequired && !requiredAllValid) || !prov.ok) verdict = 'FAIL';
    else if (mldsaValidatedValid) verdict = 'COMPLIANCE-VERIFIED' + (slhValid ? ' +diversity' : '') + (falconOnlyValid ? ' +provenance-anchored' : '');
    else if (falconOnlyValid && !mldsaValidatedValid) verdict = 'PROVENANCE-ONLY';
    else verdict = legs.some((l) => l.alg === 'ML-DSA-87' && l.valid) ? 'SIGNED (untrusted issuer or module not asserted validated — NOT compliance-verified)' : 'UNVERIFIED';

    return { verdict, legs, provenance: prov, unsubstantiated, pqrs: { computed: pqrs, embedded, match: pqrsMatch }, errors, reasons };
  } catch (e) { return fail('error: ' + (e && e.message || e)); }
  function fail(msg) { return { verdict: 'FAIL', legs, errors: errors.concat(msg), reasons }; }
}

/* ---------- self-test (node pqef.mjs): builds a real ML-DSA-87-signed bundle and verifies it ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) { pass++; } else { fail++; console.error('FAIL:', m); } };
  const seed = new Uint8Array(32).fill(9), kp = ml_dsa87.keygen(seed), ctx = 'pqef-statement-v0.1';
  const statement = {
    pqef_version: '0.1', statement_type: 'https://pqef.org/schema/migration-evidence/0.1',
    canonicalization: 'json-jcs', hash_alg: 'SHA-384',
    subject: { org_pseudonym: 'org-7f', estimated_assets: 1000, system: { name: 'core', boundary_id: 'b1', env: 'prod' }, scope: 'TLS+code-signing; excludes legacy mainframe' },
    collected_at: '2026-06-25T00:00:00Z',
    migration_state: { totals: { inventoried: 1000, assessed: 1000, planned: 800, in_migration: 400, hybrid_deployed: 200, pqc_deployed: 90, verified: 60, exception: 20 },
      fips_module: { cmvp_cert: 'CMVP #0000', validated: true } },
    collectors: [{ collector_id: 'c1', type: 'kms_connector' }, { collector_id: 'c2', type: 'automated_scanner' }],
    control_mappings: [{ framework: 'NIST_SP_800-53r5', control_id: 'SC-13', status: 'met' }, { framework: 'CNSA_2.0', control_id: 'x', status: 'compensating' }, { framework: 'NIS2', control_id: 'art21', status: 'not_met' }],
    provenance: { steps: [{ step_id: 'p0', action: 'collect', prev: null }, { step_id: 'p1', action: 'review', prev: 'p0' }, { step_id: 'p2', action: 'sign', prev: 'p1' }] },
  };
  // compute PQRS, embed it (a real producer would do this), then sign the canonical bytes
  const pre = computePQRS(statement, true, true, false);
  statement.readiness_score = { model_version: pre.model_version, subscores: pre.subscores, pqrs: pre.pqrs };
  const signedBytes = te(canonicalize(statement));
  const sig = ml_dsa87.sign(signedBytes, kp.secretKey, { context: te(ctx) });
  const bundle = { pqef_version: '0.1', statement,
    envelope: { signatures: [{ alg: 'ML-DSA-87', required: true, validated_module: true, key_id: 'k1', context: ctx, public_key_hex: bytesToHex(kp.publicKey), sig_hex: bytesToHex(sig) }] } };

  const trustedIssuers = [{ key_id: 'k1', public_key_hex: bytesToHex(kp.publicKey) }];
  const good = await verifyPQEFBundle(bundle, { trustedIssuers });
  ok(good.verdict.startsWith('COMPLIANCE-VERIFIED'), 'valid bundle + TRUSTED issuer -> COMPLIANCE-VERIFIED (got ' + good.verdict + ')');
  ok(good.pqrs.match === true, 'recomputed PQRS matches embedded (' + good.pqrs.computed.pqrs + ')');
  ok(good.errors.length === 0, 'no errors on a clean bundle');

  // SELF-ATTESTATION ATTACK (council regression): the same valid bundle with NO trusted issuer
  // (or an attacker key) must NOT be COMPLIANCE-VERIFIED — a self-signed bundle can't claim compliance.
  const selfAttest = await verifyPQEFBundle(bundle); // no trustedIssuers
  ok(!selfAttest.verdict.startsWith('COMPLIANCE-VERIFIED'), 'self-signed bundle, no trusted issuer -> NOT compliance-verified (got ' + selfAttest.verdict + ')');

  // tamper: flip one statement field AFTER signing -> signature must fail
  const tampered = JSON.parse(JSON.stringify(bundle)); tampered.statement.subject.scope = 'TAMPERED';
  const bad = await verifyPQEFBundle(tampered);
  ok(bad.verdict === 'FAIL', 'tampered statement -> FAIL (got ' + bad.verdict + ')');

  // broken provenance -> FAIL
  const brokeProv = JSON.parse(JSON.stringify(bundle)); brokeProv.statement.provenance.steps[1].prev = 'ghost';
  // re-sign so the signature is valid but provenance is broken (isolates the provenance gate)
  const sb2 = te(canonicalize(brokeProv.statement)); brokeProv.envelope.signatures[0].sig_hex = bytesToHex(ml_dsa87.sign(sb2, kp.secretKey, { context: te(ctx) }));
  const bp = await verifyPQEFBundle(brokeProv);
  ok(bp.verdict === 'FAIL' && !bp.provenance.ok, 'broken provenance -> FAIL even with a valid signature');

  // secret-material guard (named-secret blacklist still works)
  const leaky = JSON.parse(JSON.stringify(bundle)); leaky.statement.subject.private_key = 'deadbeef';
  const lk = await verifyPQEFBundle(leaky);
  ok(lk.verdict === 'FAIL' && lk.errors.some((e) => /secret-looking/.test(e)), 'secret-looking field -> FAIL');

  // SCHEMA ALLOWLIST > blacklist: a secret hidden under an INNOCUOUS name the regex misses is still caught.
  const sneaky = JSON.parse(JSON.stringify(bundle)); sneaky.statement.subject.entropy = '0xCAFEBABE-private-material';
  const sn = await verifyPQEFBundle(sneaky);
  ok(SECRET_KEY_RE.test('entropy') === false, "the name-blacklist does NOT match 'entropy' (a blacklist gap)");
  ok(sn.verdict === 'FAIL' && sn.errors.some((e) => /unknown-key/.test(e)), 'allowlist catches the innocuously-named secret field the blacklist missed -> FAIL');
  // a clean bundle has ZERO violations (no false positives — incl. statement_type URL, ISO dates, control IDs)
  ok(schemaScan(statement, SCHEMAS['0.1']).length === 0, 'a well-formed statement has no schema-guard violations (no false positives)');

  // VALUE-SMUGGLING (Moonshot fix): a secret inside an ALLOWED field's value is caught even though the key is legal
  const valSecret = JSON.parse(JSON.stringify(bundle)); valSecret.statement.subject.scope = 'migration of key ' + 'a1b2c3d4'.repeat(8); // 64-hex blob
  const vs = await verifyPQEFBundle(valSecret);
  ok(vs.verdict === 'FAIL' && vs.errors.some((e) => /secret-value/.test(e)), 'secret material inside an allowed field VALUE -> FAIL (value-scanned, not just key names)');
  // JSON-Pointer paths (Moonshot fix): violation path is unambiguous RFC-6901
  ok(vs.errors.some((e) => /secret-value:\/subject\/scope/.test(e)), 'violation path uses RFC-6901 JSON Pointer (/subject/scope)');

  // TYPE-CONFUSION (Moonshot fix): turning an allowed SCALAR field into an object is a TYPE MISMATCH (no unchecked namespace)
  const confuse = JSON.parse(JSON.stringify(bundle)); confuse.statement.subject.scope = { smuggled: 'whatever' };
  const cf = await verifyPQEFBundle(confuse);
  ok(cf.verdict === 'FAIL' && cf.errors.some((e) => /type-mismatch:\/subject\/scope/.test(e)), 'allowed scalar field turned into an object -> type-mismatch FAIL (no unchecked namespace)');

  // VALUE-TYPE constraint: a numeric field arriving as a string is rejected
  const wrongType = JSON.parse(JSON.stringify(bundle)); wrongType.statement.subject.estimated_assets = 'lots';
  const wt = await verifyPQEFBundle(wrongType);
  ok(wt.verdict === 'FAIL' && wt.errors.some((e) => /type-mismatch:\/subject\/estimated_assets/.test(e)), 'numeric field as a string -> type-mismatch FAIL');

  // VERSION PINNING (Moonshot fix): an unrecognized pqef_version has no pinned schema -> fail-closed
  const badVer = JSON.parse(JSON.stringify(bundle)); badVer.statement.pqef_version = '9.9';
  // re-sign so the signature is valid but the version is unknown (isolates the version gate)
  badVer.envelope.signatures[0].sig_hex = bytesToHex(ml_dsa87.sign(te(canonicalize(badVer.statement)), kp.secretKey, { context: te(ctx) }));
  const bv = await verifyPQEFBundle(badVer, { trustedIssuers });
  ok(bv.verdict === 'FAIL' && bv.errors.some((e) => /unsupported pqef_version/.test(e)), 'unknown pqef_version -> fail-closed (no pinned schema)');

  console.log('PQEF self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /pqef\.mjs$/.test(process.argv[1] || '')) selfTest();
