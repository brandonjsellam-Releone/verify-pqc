/*!
 * pqmarket — verifiable agent-reputation core for an agentic trust marketplace (reference, DRAFT, standalone).
 *
 * The crypto core of the agentic marketplace: AI agents publish ML-DSA-87-SIGNED capability listings; counterparties
 * issue SIGNED attestations (met / disputed) that are recorded in an APPEND-ONLY transparency log (pqsign) so they
 * can't be forged, silently retracted, or double-counted; a consumer computes a VERIFYING reputation aggregate and
 * gates delegation on it — no trusted marketplace intermediary.
 *
 * HONEST TRUST MODEL (load-bearing): the verifiable layer prevents FORGED attestations (signatures), INFLATION by a
 * single reviewer (one attestation per (reviewer, capability) pair), and silent retraction (append-only log). It does
 * NOT by itself solve SYBIL/collusion (an attacker minting many reviewer keys). So reputation is "K DISTINCT
 * attestations from reviewers the CONSUMER pins/trusts" — trust is anchored in the consumer's reviewer set, not raw
 * counts (like pqef trustedIssuers). Real-world sybil resistance needs identity/stake/web-of-trust on top. Reference,
 * unaudited. Self-test: node pqmarket.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { PQTransparencyLog, verifySTH, entryLeafHash, verifyInclusionRFC } from './pqsign.mjs';

const LISTING_CTX = utf8ToBytes('trelyan-pqmarket-listing-v1');
const ATTEST_CTX = utf8ToBytes('trelyan-pqmarket-attestation-v1');
const agentId = (pub) => bytesToHex(sha512(pub)).slice(0, 64); // 256-bit (council/NVIDIA: avoid 128-bit targeted-collision)
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

export const generateAgent = (seed) => ml_dsa87.keygen(seed);
export const agentIdOf = (agentPub) => agentId(agentPub);

/* ---------- signed capability listing ---------- */
export function publishCapability({ agent, capabilities, claims }, opts = {}) {
  // valid_from/expires_at are SIGNED (council/NVIDIA: a stale/compromised listing can't be replayed past expiry).
  const core = { kind: 'pqmarket-listing', v: '0.1', agent_id: agentId(agent.publicKey), agent_pub: bytesToHex(agent.publicKey), capabilities: (capabilities || []).slice().sort(), claims: claims || {}, valid_from: opts.validFrom ?? null, expires_at: opts.expiresAt ?? null, ts: opts.ts ?? null };
  return { ...core, sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), agent.secretKey, { context: LISTING_CTX })) };
}
export function verifyListing(listing, trustedAgentPub, opts = {}) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt field fails CLOSED, never DoS
  if (!listing || typeof listing !== 'object' || typeof listing.agent_pub !== 'string' || typeof listing.agent_id !== 'string' || typeof listing.sig !== 'string') return false;
  const { sig, ...core } = listing;
  // TOFU GUARD (round-2): with NO trustedAgentPub, verification would otherwise fall back to the listing's OWN
  // self-claimed agent_pub — i.e. any self-signed listing "verifies" its authenticity leg (reputation still gates,
  // but the identity pin is silently caller-optional). TOFU must be a DELIBERATE choice, not a silent default:
  // fail CLOSED unless the caller passes opts.allowTOFU === true (matches trustedIssuers/pinning patterns elsewhere).
  if (!trustedAgentPub && opts.allowTOFU !== true) return false;
  const pub = trustedAgentPub ? trustedAgentPub : hexToBytes(listing.agent_pub);
  if (trustedAgentPub && listing.agent_pub.toLowerCase() !== bytesToHex(trustedAgentPub).toLowerCase()) return false;
  if (agentId(pub) !== listing.agent_id) return false; // agent_id must bind the key
  const at = opts.at;
  // FAIL-CLOSED when a SIGNED freshness window can't be checked: a listing declaring valid_from/expires_at but verified
  // with NO clock would otherwise pass even when EXPIRED / not-yet-valid — defeating the anti-replay the signed window
  // exists to provide. Matches pqpay.mjs/pqvc.mjs; an explicit allowNoExpiryClock permits a deliberate time-less check.
  // (apex sweep 1 Jul — reachable via selectAgent, whose `at` has no default.)
  if ((at == null || !Number.isFinite(at)) && (listing.valid_from != null || listing.expires_at != null) && opts.allowNoExpiryClock !== true) return false; // a NON-FINITE clock (NaN/''/[] ) also can't check the window → fail closed (fix-verif 1 Jul)
  if (at != null && ((listing.valid_from != null && at < listing.valid_from) || (listing.expires_at != null && at > listing.expires_at))) return false; // freshness window
  return ml_dsa87.verify(hexToBytes(sig), utf8ToBytes(canon(core)), pub, { context: LISTING_CTX });
 } catch { return false; }
}

/* ---------- signed attestation (reviewer vouches/disputes a subject's capability outcome) ---------- */
export function makeAttestation({ reviewer, subject_agent_id, capability, outcome, evidence_ref }, opts = {}) {
  const core = { kind: 'pqmarket-attestation', v: '0.1', reviewer_pub: bytesToHex(reviewer.publicKey), subject_agent_id, capability, outcome: outcome === 'disputed' ? 'disputed' : 'met', evidence_ref: evidence_ref ?? null, ts: opts.ts ?? null };
  return { ...core, sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), reviewer.secretKey, { context: ATTEST_CTX })) };
}
const attestationSigOk = (att) => { const { sig, ...core } = att; try { return ml_dsa87.verify(hexToBytes(sig), utf8ToBytes(canon(core)), hexToBytes(att.reviewer_pub), { context: ATTEST_CTX }); } catch { return false; } };
export const logAttestation = (log, att) => ({ index: log.append(att), att });
export function verifyAttestationInclusion(arg, logPub) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt field fails CLOSED, never DoS
  const { att, inclusion, sth } = arg || {};
  if (!att || !inclusion || !sth || typeof inclusion !== 'object') return { verified: false, sthOk: false, incOk: false, sigOk: false };
  const sthOk = verifySTH(sth, logPub);
  const expected = entryLeafHash(att);
  const leafBound = bytesToHex(expected) === bytesToHex(inclusion.leaf);
  const incOk = leafBound && inclusion.tree_size === sth.tree_size && verifyInclusionRFC(expected, inclusion.index, sth.tree_size, (inclusion.proof || []).map((p) => p.sibling), hexToBytes(sth.root_hex));
  return { verified: !!(sthOk && incOk && attestationSigOk(att)), sthOk, incOk, sigOk: attestationSigOk(att) };
 } catch { return { verified: false, sthOk: false, incOk: false, sigOk: false }; }
}

/* ---------- VERIFYING reputation aggregate (computed over the APPEND-ONLY LOG) ---------- */
// Computes over the LOG itself, NOT a caller-supplied array (council/OpenAI+NVIDIA: an array lets a server OMIT
// disputes). "latest per (reviewer, subject, capability)" is decided by LOG-APPEND INDEX (a trusted total order) —
// NOT self-asserted ts (which a reviewer could backdate to erase a dispute). Counts ONLY reviewers the consumer PINS
// (sybil floor). sufficient = distinct trusted 'met' >= minDistinct AND disputed <= maxDisputes (policy).
// HONEST RESIDUAL: completeness holds within the consumer's log VIEW — the consumer must verify the log's STH and use
// a gossip/consistency-checked head (a single operator can present a truncated view; same limit as pqkt).
export function computeReputation(log, { subject_agent_id, capability, trustedReviewers = [], minDistinct = 1, maxDisputes = 0 } = {}) {
 let entries = [];
 try { entries = Array.isArray(log && log.entries) ? log.entries : []; } catch { entries = []; } // TOTAL (fuzz): tolerate a malformed/non-array/throwing-getter log
  const trusted = new Set((Array.isArray(trustedReviewers) ? trustedReviewers : []).filter((h) => typeof h === 'string').map((h) => h.toLowerCase()));
  const latest = new Map(); // (reviewer|subject|capability) -> { outcome, reviewer } ; later log index overwrites
  entries.forEach((att) => {
    try { // TOTAL (fuzz): a single throwing-getter/Proxy attestation is skipped, not fatal (a malicious log entry can't DoS the aggregate)
      if (!att || att.kind !== 'pqmarket-attestation' || att.subject_agent_id !== subject_agent_id) return;
      if (capability && att.capability !== capability) return;
      const rk = (att.reviewer_pub || '').toLowerCase();
      if (!trusted.has(rk) || !attestationSigOk(att)) return;
      latest.set(rk + '|' + att.subject_agent_id + '|' + att.capability, { outcome: att.outcome, reviewer: rk }); // append-order latest wins
    } catch { /* skip a malformed/adversarial entry */ }
  });
  const met = new Set(), disputed = new Set();
  for (const r of latest.values()) (r.outcome === 'disputed' ? disputed : met).add(r.reviewer);
  const metDistinct = [...met].filter((r) => !disputed.has(r)).length;
  return { subject_agent_id, capability: capability || null, met_distinct: metDistinct, disputed_distinct: disputed.size, sufficient: metDistinct >= minDistinct && disputed.size <= maxDisputes, min_distinct: minDistinct, max_disputes: maxDisputes };
}

// consumer gate. opts.at = current time (listing freshness). maxDisputes default 0 = strict fail-closed (one trusted
// reviewer's dispute blocks — a POLICY choice; raise maxDisputes / weight reviewers for open marketplaces).
// opts.trustedAgentPub PINS the listing's identity; WITHOUT it, selection fails closed unless opts.allowTOFU===true
// (TOFU = trust the listing's self-claimed key — a DELIBERATE choice; the accept verdict then carries tofu:true).
export function selectAgent(listing, log, { trustedAgentPub, capability, trustedReviewers, minDistinct = 1, maxDisputes = 0, at, allowTOFU } = {}) {
  // TOFU is a DELIBERATE choice: without a pin, selection fails closed unless the caller opts into allowTOFU.
  // `tofu` is surfaced on the verdict so a caller that DID opt in can see the listing authenticity was UNPINNED.
  const tofu = !trustedAgentPub && allowTOFU === true;
  if (!verifyListing(listing, trustedAgentPub, { at, allowTOFU })) return { accept: false, reason: 'listing invalid / not the pinned agent / expired / unpinned (no trustedAgentPub and allowTOFU not set)' };
  if (capability && !listing.capabilities.includes(capability)) return { accept: false, reason: 'agent does not list this capability' };
  const rep = computeReputation(log, { subject_agent_id: listing.agent_id, capability, trustedReviewers, minDistinct, maxDisputes });
  if (rep.disputed_distinct > maxDisputes) return { accept: false, reason: rep.disputed_distinct + ' dispute(s) from trusted reviewers (> maxDisputes ' + maxDisputes + ')', rep };
  if (!rep.sufficient) return { accept: false, reason: 'insufficient reputation (' + rep.met_distinct + '/' + minDistinct + ' distinct trusted reviewers)', rep };
  return { accept: true, rep, tofu }; // tofu:true => listing authenticity was TOFU (self-claimed key), NOT pinned

}

/* ---------- self-test: node pqmarket.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const agent = generateAgent(new Uint8Array(32).fill(40));
  const r1 = generateAgent(new Uint8Array(32).fill(41)), r2 = generateAgent(new Uint8Array(32).fill(42)), r3 = generateAgent(new Uint8Array(32).fill(43));
  const trusted = [bytesToHex(r1.publicKey), bytesToHex(r2.publicKey), bytesToHex(r3.publicKey)];
  const aid = agentIdOf(agent.publicKey);
  const cap = 'pqc-migration-audit';
  const att = (rev, capability, outcome, ts) => makeAttestation({ reviewer: rev, subject_agent_id: aid, capability, outcome, evidence_ref: 'job' }, { ts });

  // 1. listing + freshness window (council/NVIDIA)
  const listing = publishCapability({ agent, capabilities: [cap, 'cbom-scan'], claims: { sdk: '0.12.0' } }, { ts: 1, validFrom: 0, expiresAt: 1000 });
  ok(verifyListing(listing, agent.publicKey, { at: 500 }) === true, 'capability listing verifies under the pinned agent key (within validity)');
  ok(verifyListing(listing, agent.publicKey, { at: 5000 }) === false, 'EXPIRED listing -> FAILS (freshness window, anti-replay)');
  ok(verifyListing(listing, agent.publicKey) === false, 'apex-sweep: windowed listing verified with NO clock (opts.at omitted) -> FAILS CLOSED (closes the expiry/anti-replay fail-open)');
  ok(verifyListing(listing, agent.publicKey, { allowNoExpiryClock: true }) === true, 'apex-sweep: explicit allowNoExpiryClock -> a deliberate time-less check of a windowed listing passes');
  ok(verifyListing({ ...listing, capabilities: ['everything'] }, agent.publicKey, { at: 500 }) === false, 'tampered capability list -> listing FAILS');
  // 1b. round-2 TOFU guard: unpinned (no trustedAgentPub) must NOT silently verify against the listing's own key.
  const listing2 = publishCapability({ agent, capabilities: [cap], claims: {} }, { ts: 1 }); // no validity window -> isolates the pin/TOFU leg
  ok(verifyListing(listing2, agent.publicKey) === true, 'round-2 TOFU: PINNED listing verifies against the trusted agent key (unchanged)');
  ok(verifyListing(listing2) === false, 'round-2 TOFU: UNPINNED (no trustedAgentPub, no allowTOFU) -> FAILS CLOSED (no silent self-claimed-key TOFU)');
  ok(verifyListing(listing2, undefined, { allowTOFU: true }) === true, 'round-2 TOFU: UNPINNED + allowTOFU:true -> explicit TOFU against the self-claimed key still works');
  ok(verifyListing(listing2, null, { allowTOFU: false }) === false, 'round-2 TOFU: UNPINNED + allowTOFU:false -> still FAILS CLOSED (deliberate opt-in required)');
  // a forged self-signed listing (attacker mints its own key) must NOT pass under allowTOFU as the pinned agent
  const evil = generateAgent(new Uint8Array(32).fill(77));
  const evilListing = publishCapability({ agent: evil, capabilities: [cap], claims: {} }, { ts: 1 });
  ok(verifyListing(evilListing, agent.publicKey) === false, 'round-2 TOFU: a DIFFERENT self-signed key does NOT satisfy the pin');
  ok(verifyListing(evilListing, undefined, { allowTOFU: true }) === true && agentIdOf(evil.publicKey) !== aid, 'round-2 TOFU: allowTOFU verifies the self-signed listing but its agent_id is the ATTACKER\'s, not the pinned agent (reputation/pin still gate)');

  // 2. attestation inclusion in the append-only log
  const log = new PQTransparencyLog();
  const a1 = att(r1, cap, 'met', 10); const { index } = logAttestation(log, a1);
  logAttestation(log, att(r2, cap, 'met', 11));
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(50));
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 100 });
  ok(verifyAttestationInclusion({ att: a1, inclusion: log.inclusion(index), sth }, logKey.publicKey).verified === true, 'attestation included in the append-only log + signed');

  // 3. reputation over the LOG: 2 distinct trusted 'met' -> sufficient; selectAgent accepts
  const rep = computeReputation(log, { subject_agent_id: aid, capability: cap, trustedReviewers: trusted, minDistinct: 2 });
  ok(rep.met_distinct === 2 && rep.sufficient === true, 'two distinct trusted reviewers -> reputation sufficient (2/2)');
  ok(selectAgent(listing, log, { trustedAgentPub: agent.publicKey, capability: cap, trustedReviewers: trusted, minDistinct: 2, at: 500 }).accept === true, 'selectAgent accepts a listed, sufficiently-attested, in-validity agent');
  ok(selectAgent(listing, log, { trustedAgentPub: agent.publicKey, capability: cap, trustedReviewers: trusted, minDistinct: 2 }).accept === false, 'apex-sweep: selectAgent with NO `at` on a windowed listing -> REJECTS (fail-closed; the forgotten-clock fail-open is closed)');
  // 3b. round-2 TOFU guard on selectAgent: no trustedAgentPub -> rejected unless allowTOFU; allowTOFU verdict marks tofu:true
  ok(selectAgent(listing2, log, { capability: cap, trustedReviewers: trusted, minDistinct: 2, at: 500 }).accept === false, 'round-2 TOFU: selectAgent with NO trustedAgentPub and no allowTOFU -> REJECTS (not silently TOFU-accepted)');
  const tofuSel = selectAgent(listing2, log, { capability: cap, trustedReviewers: trusted, minDistinct: 2, at: 500, allowTOFU: true });
  ok(tofuSel.accept === true && tofuSel.tofu === true, 'round-2 TOFU: selectAgent + allowTOFU:true -> accepts AND marks the verdict tofu:true (authenticity was unpinned)');
  ok(selectAgent(listing2, log, { trustedAgentPub: agent.publicKey, capability: cap, trustedReviewers: trusted, minDistinct: 2, at: 500 }).tofu === false, 'round-2 TOFU: a PINNED accept is NOT flagged tofu (pin was honored)');

  // 4. INFLATION: one reviewer attesting 10x -> counts ONCE
  const inflLog = new PQTransparencyLog(); for (let i = 0; i < 10; i++) logAttestation(inflLog, att(r1, 'cbom-scan', 'met', 20 + i));
  ok(computeReputation(inflLog, { subject_agent_id: aid, capability: 'cbom-scan', trustedReviewers: trusted, minDistinct: 1 }).met_distinct === 1, 'one reviewer attesting repeatedly -> counted ONCE');

  // 5. SYBIL floor: 50 untrusted reviewers -> 0 counted
  const sybLog = new PQTransparencyLog(); for (let i = 0; i < 50; i++) logAttestation(sybLog, att(generateAgent(new Uint8Array(32).fill(100 + i)), 'cbom-scan', 'met', 30));
  ok(computeReputation(sybLog, { subject_agent_id: aid, capability: 'cbom-scan', trustedReviewers: trusted, minDistinct: 1 }).met_distinct === 0, '50 untrusted (sybil) attestations -> 0 (trust = pinned reviewers, not counts)');

  // 6. OMISSION-resistance + ts-gaming defense (council/OpenAI+NVIDIA): reputation reads the LOG, ordered by APPEND INDEX
  const dLog = new PQTransparencyLog();
  logAttestation(dLog, att(r1, cap, 'met', 10));
  logAttestation(dLog, att(r2, cap, 'met', 9999));        // r2 'met' with a HUGE ts...
  logAttestation(dLog, att(r2, cap, 'disputed', 1));      // ...then r2 'disputed' with a TINY ts, appended LATER
  ok(computeReputation(dLog, { subject_agent_id: aid, capability: cap, trustedReviewers: trusted }).disputed_distinct === 1, 'a later-logged dispute WINS over an earlier huge-ts "met" (log-order, not self-asserted ts -> backdating defeated)');
  ok(selectAgent(listing, dLog, { trustedAgentPub: agent.publicKey, capability: cap, trustedReviewers: trusted, minDistinct: 1, at: 500 }).accept === false, 'unresolved trusted dispute (in the log) BLOCKS selection — a server cannot hide it (computed over the log)');
  // 6b. maxDisputes policy (council/OpenAI: zero-blocks is a POLICY): raising it + enough met can pass
  logAttestation(dLog, att(r3, cap, 'met', 20));
  ok(selectAgent(listing, dLog, { trustedAgentPub: agent.publicKey, capability: cap, trustedReviewers: trusted, minDistinct: 1, maxDisputes: 1, at: 500 }).accept === true, 'maxDisputes policy: 1 tolerated dispute + sufficient met -> accepted (open-marketplace policy)');

  // 7. forged attestation (bad signature) ignored
  const fLog = new PQTransparencyLog(); fLog.append({ ...att(r1, cap, 'met', 10), reviewer_pub: bytesToHex(r3.publicKey) }); // claims r3 but r1-signed
  ok(computeReputation(fLog, { subject_agent_id: aid, capability: cap, trustedReviewers: trusted, minDistinct: 1 }).met_distinct === 0, 'forged attestation (sig vs claimed reviewer mismatch) -> not counted');

  console.log('pqmarket self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqmarket\.mjs$/.test(process.argv[1] || '')) selfTest();
