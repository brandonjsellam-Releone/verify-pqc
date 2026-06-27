/*!
 * pqanswer — AI-answer provenance notary (reference, DRAFT, standalone). Tier-2.
 *
 * The "cryptographic notary for AI": LLM/retrieval/agentic-browse are COMMODITY and out of scope.
 * This module binds an answer to the EXACT query + source chunks it was generated from, under an
 * ML-DSA-87 signature, verifiable offline against a PINNED signer.
 *
 * HONEST LIMIT (council): this proves PROVENANCE, not TRUTH and not SUPPORT. It attests only that
 * "this answer was generated for this query using these source snapshots at this time by this
 * signer." The listed sources may be genuine yet NOT support the answer (cherry-picking is possible);
 * it says nothing about relevance, completeness, or factual correctness. A signed hallucination is
 * still a hallucination. (Per-claim→chunk attribution + a retrieval-scope commitment are the v0.2
 * upgrades that would raise this from "provenance" toward "auditable support"; deferred.)
 *
 * Trust-root lesson (PQEF review): verification REQUIRES a pinned trustedSigners set; a valid
 * signature under a bundle-supplied key proves nothing on its own. Selective disclosure: a dossier
 * can be BINDING-verified by hashes alone (without revealing source content) — but that is NOT a
 * full CONTENT verification, and the two are reported distinctly.
 *
 * ML-DSA-87 via @noble. Composes with pqsign (log the dossier hash) + PQEF. Self-test: node pqanswer.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const CTX = utf8ToBytes('trelyan-answer-provenance-v1');
const sha = (s) => bytesToHex(sha256(typeof s === 'string' ? utf8ToBytes(s) : s));

// canonical JSON (sorted keys); production = deterministic CBOR / RFC 8785.
function canonicalize(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}
const dossierCore = (d) => utf8ToBytes(canonicalize({
  v: d.v, query_sha256: d.query_sha256, sources: d.sources, answer_sha256: d.answer_sha256,
  model: d.model, nonce: d.nonce ?? null, ts: d.ts,
}));
// canonical source order: sort by (url, content_sha256) so order/duplicates are unambiguous
const sortSources = (arr) => arr.slice().sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : (a.content_sha256 < b.content_sha256 ? -1 : a.content_sha256 > b.content_sha256 ? 1 : 0)));

export function generateNotaryKey(seed) { return ml_dsa87.keygen(seed); }

/* ---------- notarize ---------- */
export function notarizeAnswer({ query, sources, answer, model }, signerSecret, signerPub, opts = {}) {
  const dossier = {
    v: '0.1',
    query_sha256: sha(query),
    sources: sortSources((sources || []).map((s) => ({ url: s.url, content_sha256: sha(s.content) }))),
    answer_sha256: sha(answer),
    model: model || 'unspecified',
    nonce: opts.nonce || null,        // bind a verifier-supplied request nonce to defeat replay
    ts: opts.ts ?? Date.now(),
  };
  dossier.signer_pub_hex = bytesToHex(signerPub);
  dossier.sig_hex = bytesToHex(ml_dsa87.sign(dossierCore(dossier), signerSecret, { context: CTX }));
  return dossier;
}

/* ---------- verify ---------- */
export function verifyAnswer(dossier, evidence, opts = {}) {
  const trusted = (opts.trustedSigners || []).map((h) => h.toLowerCase());
  const signer_trusted = trusted.includes((dossier.signer_pub_hex || '').toLowerCase());
  let signature_valid = false;
  try { signature_valid = ml_dsa87.verify(hexToBytes(dossier.sig_hex), dossierCore(dossier), hexToBytes(dossier.signer_pub_hex), { context: CTX }); } catch { signature_valid = false; }
  const nonceOk = !opts.expectedNonce || ((dossier.nonce || '').toLowerCase() === opts.expectedNonce.toLowerCase());

  // content binding (selective disclosure: any omitted field -> null = not checked)
  let queryOk = null, answerOk = null, sourcesOk = null;
  if (evidence) {
    if (evidence.query !== undefined) queryOk = sha(evidence.query) === dossier.query_sha256;
    if (evidence.answer !== undefined) answerOk = sha(evidence.answer) === dossier.answer_sha256;
    if (Array.isArray(evidence.sources)) {
      const dset = new Set((dossier.sources || []).map((s) => s.url + '|' + s.content_sha256)); // order/dup-safe set compare
      sourcesOk = evidence.sources.length === (dossier.sources || []).length && evidence.sources.every((s) => dset.has(s.url + '|' + sha(s.content)));
    }
  }
  const suppliedPass = [queryOk, answerOk, sourcesOk].filter((x) => x !== null).every(Boolean);
  const binding_verified = signature_valid && signer_trusted && nonceOk && queryOk !== false && answerOk !== false && sourcesOk !== false;
  const content_verified = binding_verified && sourcesOk === true && queryOk === true && answerOk === true; // requires sources supplied + matched
  const evidence_match = (queryOk === null && answerOk === null && sourcesOk === null) ? 'none' : (suppliedPass ? (sourcesOk === true ? 'full' : 'partial') : 'mismatch');

  return {
    verified: content_verified,            // STRICT: only true when full content (incl. sources) was checked
    binding_verified, content_verified, signature_valid, signer_trusted, nonceOk,
    queryOk, answerOk, sourcesOk, evidence_match,
    note: !signer_trusted ? 'signer NOT in trustedSigners — provenance not established (a valid signature under an untrusted key proves nothing).'
      : !signature_valid ? 'signature invalid.'
        : !nonceOk ? 'nonce mismatch — possible replay or wrong request binding.'
          : !suppliedPass ? 'supplied evidence does not match the signed hashes (query/answer/source tampered).'
            : content_verified ? 'PROVENANCE VERIFIED. Attests ONLY that this answer was generated for this query using these source snapshots at this time by this TRUSTED signer. It does NOT attest relevance, support, completeness, or factual correctness — listed sources may be genuine yet not support the answer.'
              : 'BINDING VERIFIED (authentic dossier from a trusted signer); source CONTENT not supplied (selective disclosure) — this is NOT a full content verification.',
  };
}

/* ---------- self-test: node pqanswer.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const notary = generateNotaryKey(new Uint8Array(32).fill(5));
  const trustedSigners = [bytesToHex(notary.publicKey)];
  const input = {
    query: 'What is CNSA 2.0’s signature requirement?',
    sources: [
      { url: 'https://example.gov/cnsa2', content: 'CNSA 2.0 specifies ML-DSA (FIPS 204) for signatures.' },
      { url: 'https://example.gov/timeline', content: 'Transition target windows run toward 2030-2033.' },
    ],
    answer: 'CNSA 2.0 requires ML-DSA (FIPS 204) for digital signatures.',
    model: 'trelyan-answer-engine/1.0',
  };
  const dossier = notarizeAnswer(input, notary.secretKey, notary.publicKey, { ts: 1000, nonce: 'a1b2c3' });

  const good = verifyAnswer(dossier, input, { trustedSigners, expectedNonce: 'a1b2c3' });
  ok(good.verified === true, 'valid answer + trusted signer + matching evidence + nonce -> VERIFIED (content)');
  ok(good.content_verified && good.signature_valid && good.signer_trusted && good.sourcesOk && good.evidence_match === 'full', 'all content-verification flags true');

  // tampered answer / source -> not verified
  ok(verifyAnswer(dossier, { ...input, answer: 'CNSA 2.0 requires RSA-2048.' }, { trustedSigners }).answerOk === false, 'tampered answer -> answerOk false');
  ok(verifyAnswer(dossier, { ...input, sources: [{ ...input.sources[0], content: 'fabricated' }, input.sources[1]] }, { trustedSigners }).sourcesOk === false, 'tampered source -> sourcesOk false');

  // source REORDERING must still verify (order/duplicate-safe binding — council fix)
  ok(verifyAnswer(dossier, { ...input, sources: [input.sources[1], input.sources[0]] }, { trustedSigners }).sourcesOk === true, 'reordered sources still verify (canonical set binding)');

  // untrusted signer -> not verified even with valid signature (trust-root)
  const untrusted = verifyAnswer(dossier, input, { trustedSigners: [] });
  ok(untrusted.verified === false && untrusted.signer_trusted === false, 'untrusted signer -> NOT verified');

  // attacker-signed dossier rejected under the real notary pin
  const evil = generateNotaryKey(new Uint8Array(32).fill(9));
  const forged = notarizeAnswer(input, evil.secretKey, evil.publicKey, { ts: 1000 });
  ok(verifyAnswer(forged, input, { trustedSigners }).signer_trusted === false, 'attacker-signed dossier rejected under the real notary pin');

  // replay/nonce: wrong expected nonce -> not verified (council fix)
  ok(verifyAnswer(dossier, input, { trustedSigners, expectedNonce: 'deadbeef' }).nonceOk === false, 'wrong nonce -> nonceOk false (replay defence)');

  // selective disclosure: hashes-only is BINDING-verified but NOT content-verified (council fix to semantics)
  const hashesOnly = verifyAnswer(dossier, { query: input.query, answer: input.answer }, { trustedSigners, expectedNonce: 'a1b2c3' });
  ok(hashesOnly.binding_verified === true && hashesOnly.verified === false && hashesOnly.sourcesOk === null, 'selective disclosure -> binding_verified true, content verified FALSE (sources not shown)');

  console.log('pqanswer self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqanswer\.mjs$/.test(process.argv[1] || '')) selfTest();
