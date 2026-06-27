/*!
 * pqvault — long-term confidentiality vault (reference, DRAFT, standalone).
 *
 * Top-10 product #7. Data-at-rest that must stay secret for DECADES under "harvest-now / decrypt-later": each entry
 * is sealed in a HYBRID X25519 + ML-KEM-1024 envelope to a long-term custody key (so the PQ leg protects today's
 * ciphertext against a future quantum adversary), and the vault keeps a SIGNED, APPEND-ONLY MANIFEST (a pqsign
 * RFC-6962 Merkle log of put/rotate events binding each entry's envelope hash) — so you can prove WHAT is in the
 * vault and that it wasn't altered, and CRYPTO-AGILITY lets you re-seal entries to a new custody key/suite as
 * algorithms evolve, with the rotation recorded.
 *
 * Composition: envelope/seal/rotate = polarseek (hardened); manifest = pqsign (RFC-6962 inclusion, index/tree_size
 * bound). The per-envelope KEK is EPHEMERAL (transcript-bound to a fresh X25519+ML-KEM contribution per seal), so it
 * wraps exactly ONE DEK — no GCM-nonce birthday concern across entries.
 * HONEST LIMITS (full 11-seat council): (1) ROLLBACK — verifyEntry takes the LATEST leaf for the id within the
 * provided STH (no caller index), but a fresh STH is the RELYING PARTY's responsibility; a single operator can serve
 * an internally-consistent OLD snapshot, so cross-view freshness needs the witness/gossip layer (same as pqkt). (2)
 * Rotation protects FUTURE seals only — already-harvested ciphertext stays decryptable under the old key (inherent to
 * any re-encryption). (3) Single-recipient custody (K-of-N threshold via secret sharing = roadmap); custody key is
 * long-lived BY DESIGN (KMS custody, not messaging FS). (4) GDPR: pseudonymize entry ids, never raw PII; erasure =
 * crypto-shred (discard the custody key). (5) Persistent deployments need a WAL so put+manifest-append are atomic.
 * Reference, unaudited. Self-test: node pqvault.mjs
 */
import * as polarseek from './polarseek.mjs';
import { PQTransparencyLog, verifySTH, leafHash, entryLeafHash, verifyInclusionRFC } from './pqsign.mjs';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export function createVault() { return { entries: new Map(), log: new PQTransparencyLog(), version: 1 }; }

// PUT: seal plaintext to the custody key (hybrid envelope + authority-signed custody record), append a manifest leaf.
export function putEntry(vault, { id, plaintext, custodyPub, authoritySecret }, opts = {}) {
  const sealed = polarseek.seal(plaintext, custodyPub, authoritySecret, { key_id: id, op: 'seal', ts: opts.ts ?? 0 });
  vault.entries.set(id, { id, envelope: sealed.envelope, custody_record: sealed.custody_record });
  const index = vault.log.append({ op: 'put', id, envelope_hash: sealed.custody_record.envelope_hash, ts: opts.ts ?? null });
  return { id, index };
}
export function getEntry(vault, id, custodySec) { const e = vault.entries.get(id); if (!e) return null; return polarseek.unseal(e.envelope, custodySec); }

// ROTATE (crypto-agility): re-seal an entry to a NEW custody key; the old key can no longer open it; manifest records it.
export function rotateEntry(vault, { id, oldCustodySec, newCustodyPub, authoritySecret }, opts = {}) {
  const e = vault.entries.get(id); if (!e) throw new Error('no such entry: ' + id);
  const rotated = polarseek.rotate(e.envelope, oldCustodySec, newCustodyPub, authoritySecret, { key_id: id, ts: opts.ts ?? 0 });
  vault.entries.set(id, { id, envelope: rotated.envelope, custody_record: rotated.custody_record });
  const index = vault.log.append({ op: 'rotate', id, envelope_hash: rotated.custody_record.envelope_hash, ts: opts.ts ?? null });
  return { id, index };
}

// the signed manifest head (publish/anchor this). logSecret = the vault-manifest signing key.
export function sealManifest(vault, logSecret, opts = {}) { return vault.log.signedTreeHead(logSecret, opts); }

// VERIFY an entry end-to-end against a SIGNED manifest head. ROLLBACK DEFENSE (council — Moonshot/OpenAI/Grok): the
// index is NOT caller-supplied; we take the LATEST put/rotate leaf for this id WITHIN the provided STH's tree, and
// require the current entry to match it — so a stale/superseded state (e.g. a pre-rotation snapshot) is rejected.
// FRESHNESS (residual, documented): `sth` MUST be a fresh head the relying party trusts (obtained via gossip /
// consistency-checked); a single operator can still present an internally-consistent OLD snapshot — cross-view
// freshness needs the same witness/gossip layer as pqkt.
export function verifyEntry(vault, id, opts = {}) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt in vault/entry fails CLOSED, never DoS
  const { authorityPub, logPub, sth } = opts || {};
  if (!vault || !vault.entries || typeof vault.entries.get !== 'function' || !vault.log) return { verified: false, reason: 'malformed vault' };
  const e = vault.entries.get(id);
  if (!e) return { verified: false, reason: 'no such entry' };
  const sthOk = verifySTH(sth, logPub);
  let index = -1; // latest put/rotate leaf for this id, within the signed tree
  for (let i = 0; i < sth.tree_size && i < vault.log.entries.length; i++) { const l = vault.log.entries[i]; if (l && l.id === id && (l.op === 'put' || l.op === 'rotate')) index = i; }
  if (index < 0) return { verified: false, sthOk, reason: 'no manifest leaf for this entry within the signed tree (stale STH?)' };
  const recOk = polarseek.verifyCustodyRecord(e.custody_record, authorityPub);
  const bindOk = polarseek.verifyCustodyBinding(e.envelope, e.custody_record);
  const inc = vault.log.inclusion(index);
  const leaf = vault.log.entries[index];
  const leafMatchesEntry = leaf.id === id && leaf.envelope_hash === e.custody_record.envelope_hash; // current entry == latest logged state
  const expectedLeaf = entryLeafHash(leaf);
  const incOk = inc.tree_size === sth.tree_size && verifyInclusionRFC(expectedLeaf, inc.index, sth.tree_size, inc.proof.map((p) => p.sibling), hexToBytes(sth.root_hex));
  const verified = recOk && bindOk && sthOk && leafMatchesEntry && incOk;
  return { verified, recOk, bindOk, sthOk, leafMatchesEntry, incOk, latestIndex: index, reason: verified ? 'entry verified (sealed, authority-signed, bound, latest state in the signed manifest)' : !sthOk ? 'manifest STH invalid' : !recOk ? 'custody record not authority-signed' : !bindOk ? 'custody record does not bind this envelope' : !leafMatchesEntry ? 'current entry is not the latest logged state (stale/rolled-back STH or superseded entry)' : 'inclusion proof failed' };
 } catch { return { verified: false, reason: 'malformed vault' }; }
}

/* ---------- self-test: node pqvault.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const custody = polarseek.generateCustodyKey();
  const authority = polarseek.generateAuthorityKey(new Uint8Array(32).fill(51));
  // manifest signing key (ML-DSA-87) via polarseek's authority generator (same scheme)
  const manifestKey = polarseek.generateAuthorityKey(new Uint8Array(32).fill(52));

  const vault = createVault();
  const p1 = putEntry(vault, { id: 'db-root-pw', plaintext: 'S3cret-master-password', custodyPub: custody.pub, authoritySecret: authority.secretKey }, { ts: 1000 });
  putEntry(vault, { id: 'signing-seed', plaintext: '0xDEADBEEF signing seed', custodyPub: custody.pub, authoritySecret: authority.secretKey }, { ts: 1001 });
  const sth1 = sealManifest(vault, manifestKey.secretKey, { ts: 2000 });

  // 1. recover plaintext
  ok(new TextDecoder().decode(getEntry(vault, 'db-root-pw', custody.sec)) === 'S3cret-master-password', 'sealed entry unseals to the original plaintext');
  // 2. wrong custody key cannot open
  let wrong = false; try { getEntry(vault, 'db-root-pw', polarseek.generateCustodyKey().sec); } catch { wrong = true; }
  ok(wrong, 'a wrong custody key cannot open the entry');
  // 3. verify entry end-to-end (authority + latest-leaf manifest inclusion; no caller index)
  ok(verifyEntry(vault, 'db-root-pw', { authorityPub: authority.publicKey, logPub: manifestKey.publicKey, sth: sth1 }).verified === true, 'entry verifies: sealed + authority-signed + bound + latest state in the signed manifest');
  // 4. tamper the stored envelope -> binding + unseal fail
  vault.entries.get('signing-seed').envelope.ciphertext = vault.entries.get('signing-seed').envelope.ciphertext.slice(0, -2) + '00';
  ok(polarseek.verifyCustodyBinding(vault.entries.get('signing-seed').envelope, vault.entries.get('signing-seed').custody_record) === false, 'tampered envelope -> custody binding FAILS (manifest hash mismatch)');

  // 5. CRYPTO-AGILITY: rotate db-root-pw to a NEW custody key; new opens, old does not; manifest records it
  const custody2 = polarseek.generateCustodyKey();
  const r = rotateEntry(vault, { id: 'db-root-pw', oldCustodySec: custody.sec, newCustodyPub: custody2.pub, authoritySecret: authority.secretKey }, { ts: 1100 });
  ok(new TextDecoder().decode(getEntry(vault, 'db-root-pw', custody2.sec)) === 'S3cret-master-password', 'rotated entry opens under the NEW custody key');
  let oldFail = false; try { getEntry(vault, 'db-root-pw', custody.sec); } catch { oldFail = true; }
  ok(oldFail, 'the OLD custody key can no longer open the rotated entry');
  const sth2 = sealManifest(vault, manifestKey.secretKey, { ts: 2100 });
  ok(verifyEntry(vault, 'db-root-pw', { authorityPub: authority.publicKey, logPub: manifestKey.publicKey, sth: sth2 }).verified === true, 'the rotated entry verifies against the FRESH signed manifest (sth2)');

  // 6. ROLLBACK DEFENSE (council): the rotated entry against a STALE pre-rotation STH (sth1) -> NOT verified
  ok(verifyEntry(vault, 'db-root-pw', { authorityPub: authority.publicKey, logPub: manifestKey.publicKey, sth: sth1 }).verified === false, 'rotated entry against a STALE STH (pre-rotation) -> NOT verified (no caller-index rollback)');

  // 7. wrong manifest signing key -> manifest verify fails
  ok(verifyEntry(vault, 'db-root-pw', { authorityPub: authority.publicKey, logPub: polarseek.generateAuthorityKey(new Uint8Array(32).fill(9)).publicKey, sth: sth2 }).sthOk === false, 'manifest under a wrong signing key -> NOT verified');

  console.log('pqvault self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqvault\.mjs$/.test(process.argv[1] || '')) selfTest();
