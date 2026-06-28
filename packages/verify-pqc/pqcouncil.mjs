/*!
 * pqcouncil — Council-run attestation (reference, DRAFT, standalone). KNOWLEDGE_BASE §F.
 * v2: hardened per the 11-seat review (roster-binding + dup-rejection close selective omission;
 * multi-witness co-signing moves it from a "signed claim" to a "witnessed record").
 *
 * Turns a Team-Apex council run into a VERIFIABLE, tamper-evident artifact: ML-DSA-87 signature(s)
 * binding the exact { question, ROSTER of (seat,model_id), each seat's response, synthesis } of a run.
 *
 * HONEST TRUST MODEL (Grok): a SINGLE signature where the runner == signer is only a *non-repudiable
 * signed claim* ("I ran these models and got these outputs"), NOT independent proof — the runner could
 * still fabricate. Real third-party assurance requires either (a) >=t independent WITNESS co-signatures
 * over the same transcript, or (b) anchoring the attestation hash in the pqsign transparency log, or
 * (c) TEE remote attestation binding the hashes to live inference. This module implements (a) + is
 * designed to compose with (b); (c) is operational/deferred.
 *
 * Selective-omission defense (DeepSeek): the signed core commits a roster_sha256; the verifier checks
 * it against an EXPECTED roster supplied out-of-band, so a dropped/dissenting seat is detectable.
 * Trust-root: verification requires PINNED trustedSigners (+ trustedWitnesses). Self-test: node pqcouncil.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const CTX = utf8ToBytes('trelyan-council-attestation-v1');
const sha = (s) => bytesToHex(sha256(typeof s === 'string' ? utf8ToBytes(s) : s));
function canonicalize(v) {
  if (v === undefined) throw new Error('canonicalize: undefined (fail-closed)');
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('canonicalize: non-finite number (fail-closed)');
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}
const core = (a) => utf8ToBytes(canonicalize({
  v: a.v, question_sha256: a.question_sha256, seats: a.seats, roster_sha256: a.roster_sha256,
  synthesis_sha256: a.synthesis_sha256, council: a.council, nonce: a.nonce ?? null, ts: a.ts,
}));
const sortSeats = (arr) => arr.slice().sort((a, b) =>
  (a.seat < b.seat ? -1 : a.seat > b.seat ? 1 : (a.model_id < b.model_id ? -1 : a.model_id > b.model_id ? 1 : (a.response_sha256 < b.response_sha256 ? -1 : a.response_sha256 > b.response_sha256 ? 1 : 0))));
// roster = unique (seat,model_id) pairs, sorted, hashed
function rosterHash(pairs) {
  const uniq = [...new Set(pairs.map((p) => p.seat + '\x1f' + p.model_id))].sort();
  return sha(canonicalize(uniq));
}
function hasDupSeats(seats) { return new Set(seats.map((s) => s.seat + '\x1f' + s.model_id)).size !== seats.length; }

export function generateCouncilKey(seed) { return ml_dsa87.keygen(seed); }

/* ---------- notarize ---------- */
export function notarizeCouncilRun({ question, seats, synthesis, council }, signerSecret, signerPub, opts = {}) {
  const seatRecs = (seats || []).map((s) => ({ seat: s.seat, model_id: s.model_id, response_sha256: sha(s.response) }));
  if (hasDupSeats(seatRecs)) throw new Error('duplicate (seat,model_id) in council run');
  const att = {
    v: '0.1',
    question_sha256: sha(question),
    seats: sortSeats(seatRecs),
    roster_sha256: rosterHash(seatRecs),
    synthesis_sha256: sha(synthesis ?? ''),
    council: council || 'trelyan-11-seat',
    nonce: opts.nonce || null,
    ts: opts.ts ?? Date.now(),
  };
  att.signatures = [{ signer_pub_hex: bytesToHex(signerPub), sig_hex: bytesToHex(ml_dsa87.sign(core(att), signerSecret, { context: CTX })), role: 'primary' }];
  return att;
}
// append an independent witness co-signature over the SAME signed core
export function addWitness(att, witnessSecret, witnessPub, role = 'witness') {
  att.signatures.push({ signer_pub_hex: bytesToHex(witnessPub), sig_hex: bytesToHex(ml_dsa87.sign(core(att), witnessSecret, { context: CTX })), role });
  return att;
}

/* ---------- verify ---------- */
export function verifyCouncilRun(att, evidence, opts = {}) {
 try { // TOTAL (3rd sweep): a malformed attestation (undefined core field via canonicalize) fails CLOSED, never throws
  if (!att || typeof att !== 'object' || Array.isArray(att)) return { verified: false, binding_verified: false, content_verified: false, primary_trusted: false, witness_count: 0, note: 'malformed attestation' };
  const trustedP = (opts.trustedSigners || []).map((h) => h.toLowerCase());
  const trustedW = (opts.trustedWitnesses || []).map((h) => h.toLowerCase());
  const cb = core(att);
  let primary_trusted = false; const witnessSet = new Set();
  for (const s of att.signatures || []) {
    let ok = false; try { ok = ml_dsa87.verify(hexToBytes(s.sig_hex), cb, hexToBytes(s.signer_pub_hex), { context: CTX }); } catch { ok = false; }
    if (!ok) continue;
    const pk = (s.signer_pub_hex || '').toLowerCase();
    if (trustedP.includes(pk)) primary_trusted = true;
    if (trustedW.includes(pk)) witnessSet.add(pk);
  }
  const witness_count = witnessSet.size;
  const nonceOk = !opts.expectedNonce || ((att.nonce || '').toLowerCase() === opts.expectedNonce.toLowerCase());

  // roster integrity + (optional) expected-roster check (closes selective omission)
  const rosterInternalOk = att.roster_sha256 === rosterHash(att.seats || []);
  const dupOk = !hasDupSeats(att.seats || []);
  const rosterOk = !opts.expectedRoster || att.roster_sha256 === rosterHash(opts.expectedRoster);

  // content binding (selective disclosure)
  let questionOk = null, synthesisOk = null, seatsOk = null;
  if (evidence) {
    if (evidence.question !== undefined) questionOk = sha(evidence.question) === att.question_sha256;
    if (evidence.synthesis !== undefined) synthesisOk = sha(evidence.synthesis) === att.synthesis_sha256;
    if (Array.isArray(evidence.seats)) {
      const dset = new Set((att.seats || []).map((s) => s.seat + '|' + s.model_id + '|' + s.response_sha256));
      seatsOk = evidence.seats.length === (att.seats || []).length && evidence.seats.every((s) => dset.has(s.seat + '|' + s.model_id + '|' + sha(s.response)));
    }
  }
  const suppliedPass = [questionOk, synthesisOk, seatsOk].filter((x) => x !== null).every(Boolean);
  const minW = opts.minWitnesses || 0;
  const witnessed = witness_count >= minW && minW > 0;
  const binding_verified = primary_trusted && nonceOk && rosterInternalOk && dupOk && rosterOk
    && questionOk !== false && synthesisOk !== false && seatsOk !== false && witness_count >= minW;
  const content_verified = binding_verified && seatsOk === true && questionOk === true && synthesisOk === true;

  return {
    verified: content_verified, binding_verified, content_verified,
    primary_trusted, witness_count, witnessed, rosterOk, rosterInternalOk, dupOk, nonceOk,
    questionOk, synthesisOk, seatsOk, seat_count: (att.seats || []).length,
    assurance: witnessed ? 'witnessed-record' : 'signed-claim',
    note: !primary_trusted ? 'no valid signature from a pinned trustedSigner — provenance not established.'
      : !nonceOk ? 'nonce mismatch — possible replay.'
        : !dupOk || !rosterInternalOk ? 'roster integrity failure (duplicate or inconsistent seats).'
          : !rosterOk ? 'roster does NOT match the expected council roster — a seat may have been omitted/added (selective omission).'
            : witness_count < minW ? 'insufficient independent witness co-signatures (' + witness_count + '/' + minW + ').'
              : !suppliedPass ? 'supplied evidence does not match the signed transcript (tampered).'
                : content_verified
                  ? (witnessed
                    ? 'COUNCIL RUN VERIFIED as a WITNESSED RECORD (>=' + minW + ' independent witnesses co-signed the same transcript). Attests WHAT ran, not that the synthesis is correct.'
                    : 'COUNCIL RUN VERIFIED as a SIGNED CLAIM by the runner (non-repudiable, tamper-evident) — NOT independent proof; add witness co-signers or anchor to the transparency log for third-party assurance.')
                  : 'BINDING VERIFIED; full transcript not supplied (selective disclosure).',
  };
 } catch { return { verified: false, binding_verified: false, content_verified: false, primary_trusted: false, witness_count: 0, note: 'malformed attestation' }; }
}

/* ---------- self-test: node pqcouncil.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const runner = generateCouncilKey(new Uint8Array(32).fill(7));
  const w1 = generateCouncilKey(new Uint8Array(32).fill(8));
  const w2 = generateCouncilKey(new Uint8Array(32).fill(9));
  const trustedSigners = [bytesToHex(runner.publicKey)];
  const trustedWitnesses = [bytesToHex(w1.publicKey), bytesToHex(w2.publicKey)];
  const seats = [
    { seat: 'deepseek', model_id: 'deepseek-v4-pro', response: 'Harden the council pipeline first.' },
    { seat: 'grok', model_id: 'grok-4.3', response: 'Add independent witnesses; otherwise it is a signed claim.' },
    { seat: 'moonshot', model_id: 'kimi-k2.7', response: 'Separate deliberation from action.' },
  ];
  const run = { question: 'Top fixes?', council: 'trelyan-11-seat', seats, synthesis: 'Build root; secure agents; own standard.' };
  const expectedRoster = seats.map((s) => ({ seat: s.seat, model_id: s.model_id }));
  const att = notarizeCouncilRun(run, runner.secretKey, runner.publicKey, { ts: 1000, nonce: 'run-42' });

  const good = verifyCouncilRun(att, run, { trustedSigners, expectedNonce: 'run-42', expectedRoster });
  ok(good.verified === true && good.assurance === 'signed-claim', 'valid run, roster matches -> VERIFIED as signed-claim');

  // SELECTIVE OMISSION: an attestation built from only 2 seats fails against the expected 3-seat roster
  const omitted = notarizeCouncilRun({ ...run, seats: seats.slice(0, 2) }, runner.secretKey, runner.publicKey, { ts: 1000, nonce: 'run-42' });
  const omitRes = verifyCouncilRun(omitted, { ...run, seats: seats.slice(0, 2) }, { trustedSigners, expectedRoster });
  ok(omitRes.verified === false && omitRes.rosterOk === false, 'omitted seat -> rosterOk false (selective omission caught)');

  // WITNESSED RECORD: add 2 witnesses, require >=2
  addWitness(att, w1.secretKey, w1.publicKey); addWitness(att, w2.secretKey, w2.publicKey);
  const wRes = verifyCouncilRun(att, run, { trustedSigners, trustedWitnesses, minWitnesses: 2, expectedNonce: 'run-42', expectedRoster });
  ok(wRes.verified === true && wRes.witnessed === true && wRes.assurance === 'witnessed-record' && wRes.witness_count === 2, 'two witnesses co-sign -> witnessed-record');

  // require 2 witnesses but only 1 present -> not verified
  const att1w = notarizeCouncilRun(run, runner.secretKey, runner.publicKey, { ts: 1000, nonce: 'run-42' });
  addWitness(att1w, w1.secretKey, w1.publicKey);
  ok(verifyCouncilRun(att1w, run, { trustedSigners, trustedWitnesses, minWitnesses: 2, expectedRoster }).verified === false, 'insufficient witnesses (1/2) -> NOT verified');

  // tamper a seat response, untrusted signer, nonce
  ok(verifyCouncilRun(att, { ...run, seats: seats.map((s, i) => i === 1 ? { ...s, response: 'FAKE' } : s) }, { trustedSigners, expectedRoster }).seatsOk === false, 'tampered seat -> seatsOk false');
  ok(verifyCouncilRun(att, run, { trustedSigners: [], expectedRoster }).verified === false, 'untrusted signer -> NOT verified');
  ok(verifyCouncilRun(att, run, { trustedSigners, expectedNonce: 'wrong', expectedRoster }).nonceOk === false, 'wrong nonce -> nonceOk false');

  // duplicate seat rejected at notarize
  let dupRej = false; try { notarizeCouncilRun({ ...run, seats: [seats[0], seats[0]] }, runner.secretKey, runner.publicKey, {}); } catch { dupRej = true; }
  ok(dupRej, 'duplicate (seat,model_id) rejected at notarize');

  console.log('pqcouncil self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqcouncil\.mjs$/.test(process.argv[1] || '')) selfTest();
