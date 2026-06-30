/*!
 * pqfirmware — QuantumShield IoT: post-quantum firmware-manifest signing + anti-rollback (reference, DRAFT).
 *
 * A vendor hybrid-signs a firmware MANIFEST — { device_model, version, build_id, artifact_sha256, size, ... } — with
 * Ed25519 ∧ ML-DSA-87 ∧ optional SLH-DSA-256f. A device verifies, BEFORE flashing, that: the manifest is authentically
 * signed by the PINNED vendor; the firmware binary it received hashes to the manifest's artifact_sha256; the version is
 * STRICTLY NEWER than what's installed (monotonic anti-rollback); and it matches the device model. Only then does it flash.
 *
 * FALSIFIABLE PROPERTIES: given the manifest + the PINNED vendor keys, the device can verify (1) the vendor (whose id
 * binds its keys) signed THIS exact firmware — forging needs a classical AND lattice [AND hash-based] break; (2) the
 * received binary is the signed one (artifact hash binding); (3) it cannot be rolled back to an older signed image
 * (version > installed); (4) it is for this model. The anti-rollback is the IoT-critical bit: a signed-but-old vulnerable
 * image is rejected, so re-flashing it is not an attack path. Unaudited reference implementation.
 *
 * Dependency-light: @noble/curves (ed25519) + @noble/post-quantum (ml-dsa-87, slh-dsa) + @noble/hashes (sha256).
 * Self-test: node pqfirmware.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

const FW_CTX = utf8ToBytes('trelyan-quantumshield-fw-v1');         // signing domain (Ed25519 + ML-DSA legs)
const FW_SLH_CTX = utf8ToBytes('trelyan-quantumshield-fw-slh-v1'); // distinct domain for the optional SLH-DSA leg

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
// vendor id binds the COMPLETE hybrid key set (full 256-bit).
export function makeVendorId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('vendor keys must be { ed, mldsa[, slh] }');
  return 'vendor:trelyan:' + bytesToHex(sha256(concatBytes(utf8ToBytes('vendor:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}
function fwCore(m) {
  return { v: '1', vendor: m.vendor, device_model: m.device_model, version: m.version, build_id: m.build_id, artifact_sha256: m.artifact_sha256, size: m.size ?? null, released_at: m.released_at ?? null, min_version: m.min_version ?? null, notes: m.notes ?? null };
}

// vendorKeys = { ed, mldsa[, slh] }. Provide artifactBytes (hashed here) OR artifactSha256 (hex). version = non-negative integer.
export function signFirmware({ vendorKeys, deviceModel, version, buildId, artifactBytes, artifactSha256, size, releasedAt, minVersion, notes }) {
  if (!vendorKeys || !vendorKeys.ed || !vendorKeys.mldsa) throw new Error('vendorKeys must be { ed, mldsa[, slh] }');
  if (!Number.isInteger(version) || version < 0) throw new Error('version must be a non-negative integer (monotonic)');
  if (!deviceModel || !buildId) throw new Error('deviceModel and buildId are required');
  const art = artifactBytes ? bytesToHex(sha256(artifactBytes)) : String(artifactSha256 || '');
  if (!/^[0-9a-f]{64}$/i.test(art)) throw new Error('provide artifactBytes or a 32-byte hex artifactSha256');
  const core = fwCore({ vendor: makeVendorId(vendorKeys), device_model: String(deviceModel), version, build_id: String(buildId),
    artifact_sha256: art.toLowerCase(), size: size ?? (artifactBytes ? artifactBytes.length : null), released_at: releasedAt ?? null, min_version: minVersion ?? null, notes: notes ?? null });
  const coreBytes = utf8ToBytes(canon(core));
  const manifest = { ...core,
    vendor_pub: { ed: bytesToHex(_pub(vendorKeys.ed)), mldsa: bytesToHex(_pub(vendorKeys.mldsa)) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(FW_CTX, coreBytes), vendorKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, vendorKeys.mldsa.secretKey, { context: FW_CTX })) };
  if (vendorKeys.slh) { manifest.vendor_pub.slh = bytesToHex(_pub(vendorKeys.slh)); manifest.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, vendorKeys.slh.secretKey, { context: FW_SLH_CTX })); }
  return manifest;
}

// device-side verify-before-flash. TOTAL / fail-closed. trustedVendor = { ed, mldsa[, slh] } pinned (burned into the device).
// opts: artifactBytes (bind the received binary — REQUIRED by default), currentVersion (anti-rollback — only
// strictly-newer flashes; the device MUST supply its installed version), deviceModel (bind the model),
// allowUnboundArtifact (DANGEROUS escape hatch for metadata-only checks — skips binding the actual binary).
export function verifyFirmware(manifest, trustedVendor, opts = {}) {
  try {
    if (!manifest || typeof manifest !== 'object' || !trustedVendor || !trustedVendor.ed || !trustedVendor.mldsa) return { verified: false };
    if (!Number.isInteger(manifest.version) || manifest.version < 0) return { verified: false, reason: 'version not a non-negative integer' };
    if (manifest.vendor !== makeVendorId(trustedVendor)) return { verified: false, reason: 'vendor id != pinned vendor keys' };
    const coreBytes = utf8ToBytes(canon(fwCore(manifest)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(manifest.ed_sig), concatBytes(FW_CTX, coreBytes), trustedVendor.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(manifest.mldsa_sig), coreBytes, trustedVendor.mldsa, { context: FW_CTX }); } catch { pqOk = false; }
    if (trustedVendor.slh) { try { slhOk = !!(manifest.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(manifest.slh_sig), coreBytes, trustedVendor.slh, { context: FW_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'hybrid signature invalid (or required leg missing)' };
    // ANTI-ROLLBACK is the IoT-critical property — it must NEVER be silently skipped. Require a valid INTEGER
    // currentVersion (the device's installed version; -1 = first install) unless an explicit metadata-only opt-out. A
    // non-integer currentVersion would coerce to NaN and disable BOTH the rollback and the min_version floor (DeepSeek
    // 1 Jul, CRITICAL: a forgotten/corrupted version would otherwise flash a signed-but-OLD vulnerable firmware).
    if (opts.currentVersion != null && !Number.isInteger(opts.currentVersion)) return { verified: false, reason: 'currentVersion must be an integer (a non-integer would disable anti-rollback via NaN)' };
    if (opts.currentVersion == null && opts.allowNoRollbackCheck !== true) return { verified: false, reason: 'currentVersion required to enforce anti-rollback (installed version, -1 for first install; or set allowNoRollbackCheck for a metadata-only check)' };
    // model binding: a forgotten deviceModel → cross-model flash (bricking). Signal whether it was checked; requireModel forces it.
    if (opts.requireModel === true && opts.deviceModel == null) return { verified: false, reason: 'requireModel: supply deviceModel to bind the hardware (prevents a cross-model flash)' };
    // artifact binding: the received binary MUST hash to the signed digest. SAFE DEFAULT (apex-team fix): if no binary
    // is supplied, REJECT — a valid manifest signature must NEVER be mistaken for a verified payload. The only skip is
    // the explicit, dangerous opts.allowUnboundArtifact (metadata-only checks); production always passes artifactBytes.
    let artifactOk;
    if (opts.artifactBytes) artifactOk = bytesToHex(sha256(opts.artifactBytes)).toLowerCase() === manifest.artifact_sha256;
    else artifactOk = opts.allowUnboundArtifact === true;
    // anti-rollback: only flash a STRICTLY newer version; and honour a forced-upgrade floor (min_version)
    const rollback = opts.currentVersion != null && manifest.version <= Number(opts.currentVersion);
    const belowFloor = manifest.min_version != null && opts.currentVersion != null && Number(opts.currentVersion) < Number(manifest.min_version);
    const wrongModel = opts.deviceModel != null && manifest.device_model !== String(opts.deviceModel);
    const verified = artifactOk && !rollback && !belowFloor && !wrongModel;
    return { verified, artifactOk, rollback, belowFloor, wrongModel, rollback_checked: opts.currentVersion != null, model_checked: opts.deviceModel != null, vendor: manifest.vendor, device_model: manifest.device_model, version: manifest.version, build_id: manifest.build_id };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqfirmware.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const vendor = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const tVendor = { ed: vendor.ed.publicKey, mldsa: vendor.mldsa.publicKey };
  const attacker = { ed: ed(9), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) };
  const binary = new Uint8Array(2048).fill(0xab);   // pretend firmware image

  const m = signFirmware({ vendorKeys: vendor, deviceModel: 'TRLN-Sensor-A', version: 7, buildId: 'b-7', artifactBytes: binary, releasedAt: 1000 });
  ok(m.vendor === makeVendorId(vendor) && m.artifact_sha256 === bytesToHex(sha256(binary)), 'manifest binds vendor id + artifact hash');
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, currentVersion: 6, deviceModel: 'TRLN-Sensor-A' }).verified === true, 'valid + newer + matching binary/model -> verifies (flash OK)');
  ok(verifyFirmware(m, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }, { artifactBytes: binary, currentVersion: 6 }).verified === false, 'wrong pinned vendor -> FAILS');
  // tampered binary (same manifest) -> artifact mismatch
  const evilBin = new Uint8Array(2048).fill(0xcd);
  ok(verifyFirmware(m, tVendor, { artifactBytes: evilBin, currentVersion: 6 }).verified === false, 'received binary != signed artifact hash -> FAILS (no swapped payload)');
  // ANTI-ROLLBACK: same or older installed version must be rejected
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, currentVersion: 7 }).verified === false, 'same version (7 vs installed 7) -> rollback REJECTED');
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, currentVersion: 8 }).verified === false, 'older firmware (v7 vs installed v8) -> rollback REJECTED (the IoT-critical guard)');
  // wrong device model
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, currentVersion: 6, deviceModel: 'TRLN-Gateway-X' }).verified === false, 'wrong device model -> FAILS (no cross-model flash)');
  // tampered manifest field (version bumped without re-sign) -> sig fails
  const t = JSON.parse(JSON.stringify(m)); t.version = 999;
  ok(verifyFirmware(t, tVendor, { artifactBytes: binary, currentVersion: 6 }).verified === false, 'tampered version (re-sign-free) -> hybrid signature FAILS');
  // SAFE DEFAULT (apex-team fix): no binary supplied -> reject (a valid manifest sig must never pass as a verified payload)
  ok(verifyFirmware(m, tVendor, { currentVersion: 6 }).verified === false, 'no artifactBytes supplied -> FAILS by default (must bind the flashed binary)');
  ok(verifyFirmware(m, tVendor, { currentVersion: 6, allowUnboundArtifact: true }).verified === true, 'explicit allowUnboundArtifact opt-out -> metadata-only verify passes (dangerous, opt-in only)');
  // min_version forced-upgrade floor
  const m2 = signFirmware({ vendorKeys: vendor, deviceModel: 'TRLN-Sensor-A', version: 20, buildId: 'b-20', artifactBytes: binary, minVersion: 15 });
  ok(verifyFirmware(m2, tVendor, { artifactBytes: binary, currentVersion: 10 }).verified === false && verifyFirmware(m2, tVendor, { artifactBytes: binary, currentVersion: 16 }).verified === true, 'min_version floor: device below floor rejected, at/above floor accepted');

  // DeepSeek 1 Jul (CRITICAL): anti-rollback must NOT be silently skippable
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, deviceModel: 'TRLN-Sensor-A' }).verified === false, 'currentVersion omitted → refused (anti-rollback cannot be silently skipped)');
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, currentVersion: 'abc', deviceModel: 'TRLN-Sensor-A' }).verified === false, 'non-integer currentVersion (would NaN-disable the version checks) → refused');
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, currentVersion: -1, deviceModel: 'TRLN-Sensor-A' }).verified === true, 'first-install currentVersion=-1 → newer firmware verifies');
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, currentVersion: 6, requireModel: true }).verified === false, 'requireModel without deviceModel → refused (no cross-model flash)');
  ok(verifyFirmware(m, tVendor, { artifactBytes: binary, allowNoRollbackCheck: true, deviceModel: 'TRLN-Sensor-A' }).rollback_checked === false, 'allowNoRollbackCheck → metadata-only path; rollback_checked=false signaled');
  // version must be a non-negative integer
  let badV = false; try { signFirmware({ vendorKeys: vendor, deviceModel: 'x', version: 1.5, buildId: 'b', artifactBytes: binary }); } catch { badV = true; }
  ok(badV, 'non-integer version rejected at signing');

  // 3-leg hash-based hardening
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const vendor3 = { ed: vendor.ed, mldsa: vendor.mldsa, slh };
  const tVendor3 = { ed: tVendor.ed, mldsa: tVendor.mldsa, slh: slh.publicKey };
  const m3 = signFirmware({ vendorKeys: vendor3, deviceModel: 'TRLN-Sensor-A', version: 9, buildId: 'b-9', artifactBytes: binary });
  ok(typeof m3.slh_sig === 'string' && verifyFirmware(m3, tVendor3, { artifactBytes: binary, currentVersion: 8 }).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH-DSA) manifest verifies');
  const m3s = JSON.parse(JSON.stringify(m3)); m3s.slh_sig = '00';
  ok(verifyFirmware(m3s, tVendor3, { artifactBytes: binary, currentVersion: 8 }).verified === false, 'stripped SLH leg fails when vendor.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { version: 1 }, { ...m, version: 'x' }]) { try { if (verifyFirmware(bad, tVendor).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed manifests -> verified:false, never throws');

  console.log('pqfirmware self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqfirmware\.mjs$/.test(process.argv[1] || '')) selfTest();
