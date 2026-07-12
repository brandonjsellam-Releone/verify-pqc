/*!
 * qiv-pin — QIV off-chain storage adapter (reference, DRAFT). Completes the Quantum IP Vault story: qiv.mjs emits an
 * off-chain POINTER; this turns an artifact into a durably-pinnable object and, crucially, produces the VERIFIABLE
 * BINDING that makes the pointer trustworthy — a plain SHA-256 of the exact bytes, recorded IN the (signed) QIV record.
 * A third party then fetches `ipfs://<cid>`, hashes the bytes, and checks they equal the record's pointer hash. That
 * binding is offline-verifiable and does NOT require us to recompute the IPFS CID ourselves (which would mean
 * re-implementing UnixFS/dag-pb chunking and risking a subtly-wrong "verifiable CID" claim — we deliberately do not).
 *
 * HONEST / GATED:
 *  - LIVE pinning UPLOADS the artifact to an external service (Pinata/IPFS) → PUBLISHING the owner's IP. That is an OWNER
 *    action: `pin()` runs in MOCK/dry-run by default and only performs a network upload when called with
 *    { live:true, jwt, confirmOwnerApproved:true }. The module never reads .env or holds a credential — the caller passes
 *    the JWT. This reference's self-test only exercises the MOCK path; it never uploads.
 *  - The MOCK CID is deliberately NON-real (`mock-<hash>`), so it can never be mistaken for a genuine IPFS CID.
 *  - No claim that pinning makes IP "permanent" or "immutable" — a pin lasts as long as it is paid for + replicated;
 *    Arweave/Filecoin are the durability path. This adapter records a content hash so integrity is verifiable regardless.
 *  Self-test: node qiv-pin.mjs
 */
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const PINATA_ENDPOINT = 'https://api.pinata.cloud/pinning/pinFileToIPFS';
const toBytes = (x) => (x instanceof Uint8Array ? x : utf8ToBytes(String(x)));

/** contentDescriptor(bytes) — plain (untagged) content digests + size. SHA-256 is the binding a third party re-checks
 *  after fetching from IPFS; SHA-512 mirrors qiv's artifact strength. These are of the RAW bytes (no domain tag) so any
 *  standard tool can reproduce them. */
export function contentDescriptor(bytes) {
  const b = toBytes(bytes);
  return { size: b.length, sha256: bytesToHex(sha256(b)), sha512: bytesToHex(sha512(b)) };
}

const mockCid = (sha256hex) => 'mock-' + sha256hex.slice(0, 46);   // clearly NOT a real CID (real CIDv1 ≈ bafy…/bafk…)

/**
 * pin(bytes, opts) — pin an artifact to IPFS via Pinata. DEFAULT = MOCK/dry-run (no network).
 *   opts.live === true  → perform a REAL upload. Requires opts.jwt (Pinata JWT, caller-supplied, never logged) AND
 *                         opts.confirmOwnerApproved === true (this publishes the artifact — owner action). opts.name for metadata.
 * Returns { cid, uri:'ipfs://<cid>', live, source, ...contentDescriptor }.
 */
export async function pin(bytes, opts = {}) {
  const desc = contentDescriptor(bytes);
  if (opts.live !== true) {
    const cid = mockCid(desc.sha256);
    return { cid, uri: 'ipfs://' + cid, live: false, source: 'MOCK', ...desc, note: 'dry-run — no upload. Set {live:true, jwt, confirmOwnerApproved:true} to pin for real (publishes the artifact).' };
  }
  // --- LIVE path (owner-gated) ---
  if (opts.confirmOwnerApproved !== true) throw new Error('qiv-pin: live pin is OWNER-GATED — uploading publishes the artifact. Pass confirmOwnerApproved:true to proceed.');
  if (!opts.jwt || typeof opts.jwt !== 'string') throw new Error('qiv-pin: live pin needs opts.jwt (Pinata JWT, caller-supplied). The module never reads env/secrets itself.');
  const form = new FormData();
  form.append('file', new Blob([toBytes(bytes)]), opts.name || 'qiv-artifact.bin');
  if (opts.name) form.append('pinataMetadata', JSON.stringify({ name: opts.name }));
  const res = await fetch(PINATA_ENDPOINT, { method: 'POST', headers: { Authorization: 'Bearer ' + opts.jwt }, body: form });
  if (!res.ok) throw new Error('qiv-pin: Pinata upload failed HTTP ' + res.status);
  const j = await res.json();
  const cid = j.IpfsHash;
  return { cid, uri: 'ipfs://' + cid, live: true, source: 'PINATA', ...desc };
}

/** pinToOffchain(pinResult) — the qiv `offchain` object bound to a pin: ipfs scheme + the content SHA-256 the record
 *  will SIGN, so `verifyPinnedContent` can re-check fetched bytes against the inscription. Passes qiv's assertOffchain. */
export function pinToOffchain(pinResult) {
  if (!pinResult || !pinResult.uri || !pinResult.sha256) throw new Error('qiv-pin: pinResult with uri + sha256 required');
  return { kind: 'ipfs', uri: pinResult.uri, sha256: pinResult.sha256, size: pinResult.size };
}

/** verifyPinnedContent(fetchedBytes, offchain) — the offline-verifiable binding: recompute SHA-256 of the bytes fetched
 *  from `offchain.uri` and compare to the SHA-256 signed into the QIV record's pointer. Fail-closed. */
export function verifyPinnedContent(fetchedBytes, offchain) {
  try {
    if (!offchain || !offchain.sha256) return { verified: false, reason: 'offchain pointer has no content hash to check against' };
    const actual = bytesToHex(sha256(toBytes(fetchedBytes)));
    const verified = actual === offchain.sha256;
    return { verified, expected: offchain.sha256, actual, reason: verified ? 'ok' : 'content hash mismatch (fetched bytes ≠ inscribed pointer)' };
  } catch { return { verified: false, reason: 'exception' }; }
}

/* ---------------------------------------- self-test: node qiv-pin.mjs ---------------------------------------- */
async function selfTest() {
  const { inscribe, verifyInscription } = await import('./qiv.mjs');
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { slh_dsa_sha2_256f } = await import('@noble/post-quantum/slh-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n, len = 32) => new Uint8Array(len).fill(n);
  const artifact = utf8ToBytes('PATENT DRAFT bytes to be pinned to IPFS + inscribed in a Vault Cell.');

  // 1. mock pin (no network) is deterministic + clearly non-real
  const p1 = await pin(artifact);
  const p2 = await pin(artifact);
  ok(p1.cid === p2.cid && p1.live === false && p1.source === 'MOCK', 'pin: mock is deterministic, not live');
  ok(p1.cid.startsWith('mock-') && p1.uri.startsWith('ipfs://mock-'), 'pin: mock CID is obviously non-real');
  ok(p1.sha256 === contentDescriptor(artifact).sha256, 'pin: content SHA-256 recorded');

  // 2. live pin is owner-gated (never executed here)
  let gated = false; try { await pin(artifact, { live: true }); } catch (e) { gated = /OWNER-GATED/.test(e.message); }
  ok(gated, 'pin: live upload requires confirmOwnerApproved (gated)');
  let needsJwt = false; try { await pin(artifact, { live: true, confirmOwnerApproved: true }); } catch (e) { needsJwt = /needs opts.jwt/.test(e.message); }
  ok(needsJwt, 'pin: live upload needs a caller-supplied JWT (module never reads secrets)');

  // 3. pin → offchain pointer passes QIV's allowlist and is accepted by inscribe()
  const off = pinToOffchain(p1);
  ok(off.kind === 'ipfs' && off.sha256 === p1.sha256, 'pinToOffchain: ipfs pointer + content hash');
  const A = { alg: 'ML-DSA-87', ...ml_dsa87.keygen(seed(11)) };
  const B = { alg: 'SLH-DSA-256f', ...slh_dsa_sha2_256f.keygen(seed(22, 96)) };
  const C = (() => { const sk = seed(33); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })();
  const ins = inscribe({ cellId: 9, ipType: 'patent', metadata: { title: 'pinned patent' }, artifactBytes: artifact, offchain: off }, [A, B, C], null, { ts: 1 });
  const v = verifyInscription(ins, artifact, { trusted: { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey, 'Ed25519': C.publicKey }, requireKinds: ['lattice', 'hash-based', 'classical'] });
  ok(v.verified, 'inscribe: record with a pinned ipfs pointer verifies');
  ok(ins.record.offchain.sha256 === p1.sha256, 'inscribe: the pin content hash is SIGNED into the record');

  // 4. verifiable binding: correct fetched bytes pass, tampered bytes fail
  ok(verifyPinnedContent(artifact, ins.record.offchain).verified, 'verifyPinnedContent: correct bytes match the inscribed hash');
  ok(!verifyPinnedContent(utf8ToBytes('different content from IPFS'), ins.record.offchain).verified, 'verifyPinnedContent: tampered/wrong fetched bytes rejected');

  console.log(`\nqiv-pin self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
