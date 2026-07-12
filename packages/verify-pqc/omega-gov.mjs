/*!
 * omega-gov — TRELYAN OMEGA Layer 1 (Foundation) governance core (reference, DRAFT). A post-quantum-signed, M-of-N
 * THRESHOLD governance state machine for a Swiss-Stiftung-style board: proposals, per-member signed ballots, class-based
 * thresholds, a lifecycle (draft→review→vote→executed→archived / rejected), time-locked execution, a 2-of-3 emergency
 * pause, and social key rotation/recovery — all offline-verifiable and fail-closed. Each governance action is emitted as a
 * record you would inscribe in a Vault Cell (qiv) via a hash-chained PQ-signed log; broadcasting is owner-gated.
 *
 * WHAT THIS IS (precise): a VERIFIABLE REFERENCE of the constitutional logic. A board member's ballot is a per-member
 * AND-composition (ML-DSA-87 ∧ Ed25519, optional SLH-DSA-256f) via pqseal — a forged approval must break a lattice AND a
 * classical (and optionally a hash-based) scheme. `tally()` verifies every ballot against the PINNED roster, dedupes by
 * member, and compares approvals to the class threshold — TOTAL / fail-closed.
 *
 * WHAT THIS IS NOT (claim hygiene): NOT a deployed on-chain contract. The blueprint's PyTeal "constitutional smart
 * contract" requires a funded Algorand account + a deployed app = OWNER-GATED; this core lets you test the exact rules
 * offline and produces the record to inscribe. NOT legally binding governance — a Swiss Stiftung's legal authority is its
 * statutes + board, not this code; this encodes/attests decisions, it does not replace the foundation deed or counsel.
 * TOKEN-HOLDER voting (the blueprint's "67% token-holder approval", quadratic voting) is a TOKEN/securities matter and is
 * DELIBERATELY NOT IMPLEMENTED — see `tokenHolderVote()`. Falcon-1024 (FIPS 206) is DRAFT; the governance signatures here
 * are ML-DSA-87 (FIPS 204) ∧ Ed25519 — Falcon is only the optional on-chain inscription leg (qiv/pqanchor).
 *
 * Self-test: node omega-gov.mjs
 */
import { seal, openSeal } from './pqseal.mjs';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

const PROP_TAG   = utf8ToBytes('trelyan-omega-gov-proposal-v1');
const BALLOT_TAG = utf8ToBytes('trelyan-omega-gov-ballot-v1');

// Decision classes → threshold (# of approving board members required). Board = 5, emergency council = 3 (subset).
export const DECISION_CLASSES = {
  operational:   { of: 'board',     threshold: 2 },   // day-to-day
  strategic:     { of: 'board',     threshold: 3 },   // partnerships/investments/direction
  constitutional:{ of: 'board',     threshold: 4 },   // amendments/dissolution
  recovery:      { of: 'board',     threshold: 3 },   // social key rotation of a compromised member (3-of-5 remaining)
  emergency:     { of: 'emergency', threshold: 2 },   // 2-of-3 emergency council: pause
};
export const LIFECYCLE = ['draft', 'review', 'vote', 'executed', 'archived', 'rejected'];
// legal lifecycle transitions (a proposal can only move forward, or be rejected/archived)
const LIFECYCLE_NEXT = {
  draft: ['review', 'rejected'], review: ['vote', 'rejected'], vote: ['executed', 'rejected'],
  executed: ['archived'], rejected: ['archived'], archived: [],
};
export const PAUSE_MAX_MS = 72 * 3600 * 1000;   // emergency pause ≤ 72h (extendable only by a full board vote)
export const CHOICES = ['approve', 'reject', 'abstain'];

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
// a board member's signer set for pqseal (2- or 3-family AND-composition per member)
function signersOf(member) {
  const s = [
    { alg: 'ML-DSA-87', secretKey: member.mldsa.secretKey, publicKey: member.mldsa.publicKey },
    { alg: 'Ed25519', secretKey: member.ed.secretKey, publicKey: member.ed.publicKey },
  ];
  if (member.slh) s.push({ alg: 'SLH-DSA-256f', secretKey: member.slh.secretKey, publicKey: member.slh.publicKey });
  return s;
}
// pinned pubkeys for a roster entry (verify side). The roster stores HEX pubkeys (so a governance decision is
// JSON-portable — a reviewer can serialize + verify it elsewhere); openSeal wants raw bytes, so convert here. Tolerant of
// both representations (bytes or hex) for backward compatibility.
const toKeyBytes = (v) => (v instanceof Uint8Array ? v : hexToBytes(v));
function pinsOf(entry) {
  const t = { 'ML-DSA-87': toKeyBytes(entry.mldsa.publicKey), 'Ed25519': toKeyBytes(entry.ed.publicKey) };
  if (entry.slh) t['SLH-DSA-256f'] = toKeyBytes(entry.slh.publicKey);
  return t;
}
const reqKinds = (entry) => entry.slh ? ['lattice', 'hash-based', 'classical'] : ['lattice', 'classical'];

/**
 * createBoard({ members, emergencyCouncil }) — members: [{ id, ed:{publicKey[,secretKey]}, mldsa:{...}, slh?:{...} }, ...]
 *   emergencyCouncil: array of member ids (subset of members, typically 3). Returns a roster (pubkeys) + config.
 */
export function createBoard({ members, emergencyCouncil }) {
  if (!Array.isArray(members) || members.length < 3) throw new Error('omega-gov: need >=3 board members');
  const ids = members.map((m) => m.id);
  if (new Set(ids).size !== ids.length) throw new Error('omega-gov: duplicate member id');
  const ec = emergencyCouncil ?? ids.slice(0, 3);
  for (const id of ec) if (!ids.includes(id)) throw new Error('omega-gov: emergency council member not on board: ' + id);
  const hx = (v) => (v instanceof Uint8Array ? bytesToHex(v) : String(v));   // roster pubkeys as HEX → JSON-portable
  const roster = {};
  for (const m of members) roster[m.id] = { id: m.id, ed: { publicKey: hx(m.ed.publicKey) }, mldsa: { publicKey: hx(m.mldsa.publicKey) }, ...(m.slh ? { slh: { publicKey: hx(m.slh.publicKey) } } : {}) };
  return { size: members.length, member_ids: ids, emergency_ids: ec, roster };
}

// the signable core of a proposal (everything the proposer signs; ballots reference proposal_hash so they bind to it).
function proposalCore(p) {
  return { v: 'omega-gov-prop-1', proposal_id: p.proposal_id, decision_class: p.decision_class, action: p.action, payload_sha256: p.payload_sha256, proposer_id: p.proposer_id, created_ts: p.created_ts ?? null, execute_after: p.execute_after ?? null };
}
const proposalHash = (coreBytes) => bytesToHex(sha256(concatBytes(PROP_TAG, coreBytes)));

/** propose({ proposalId, decisionClass, action, payloadHash?, executeAfter?, createdTs? }, proposer) -> signed proposal. */
export function propose({ proposalId, decisionClass, action, payloadHash, executeAfter, createdTs }, proposer) {
  if (!DECISION_CLASSES[decisionClass]) throw new Error('omega-gov: unknown decision_class: ' + decisionClass);
  if (!proposalId || typeof proposalId !== 'string') throw new Error('omega-gov: proposalId (string) required');
  const core = proposalCore({ proposal_id: proposalId, decision_class: decisionClass, action: action ?? '', payload_sha256: payloadHash ?? '', proposer_id: proposer.id, created_ts: createdTs ?? null, execute_after: executeAfter ?? null });
  const coreBytes = utf8ToBytes(canon(core));
  const prop_hash = proposalHash(coreBytes);
  const sig = seal(coreBytes, signersOf(proposer));   // proposer authenticity (per-member AND-composition)
  return { core, proposal_hash: prop_hash, proposer_seal: sig };
}

// the signable core of a ballot: binds member + choice + the EXACT proposal_hash (so a ballot can't be replayed onto another proposal)
function ballotCore(b) {
  return { v: 'omega-gov-ballot-1', proposal_hash: b.proposal_hash, member_id: b.member_id, choice: b.choice, ts: b.ts ?? null, nonce: b.nonce };
}

/** castBallot(proposal, member, choice, { ts, nonce }) -> a pqseal-signed ballot bound to proposal.proposal_hash. */
export function castBallot(proposal, member, choice, { ts, nonce } = {}) {
  if (!CHOICES.includes(choice)) throw new Error('omega-gov: choice must be one of ' + CHOICES.join(','));
  if (!nonce) nonce = bytesToHex(sha256(concatBytes(BALLOT_TAG, utf8ToBytes(proposal.proposal_hash + member.id + choice + (ts ?? '')))));
  const core = ballotCore({ proposal_hash: proposal.proposal_hash, member_id: member.id, choice, ts: ts ?? null, nonce });
  const coreBytes = utf8ToBytes(canon(core));
  const bseal = seal(coreBytes, signersOf(member));
  return { core, ballot_seal: bseal };
}

/**
 * tally(proposal, ballots, board, opts?) — TOTAL / fail-closed.
 *   Verifies proposal proposer_seal + every ballot against the PINNED roster (per-member AND-composition), dedupes by
 *   member (last ballot wins is DISALLOWED — a member may vote once; a second distinct ballot from the same member is an
 *   error flagged in doubleVoters), counts approvals among ELIGIBLE members (emergency class => only emergency council),
 *   and compares to the class threshold. opts.now enforces the execute_after time-lock.
 * Returns { class, threshold, approvals, rejections, executable, reason, invalidBallots, doubleVoters, timeLocked }.
 */
export function tally(proposal, ballots, board, opts = {}) {
  const fail = (reason) => ({ class: null, threshold: null, approvals: 0, rejections: 0, executable: false, reason, invalidBallots: [], doubleVoters: [], timeLocked: false });
  try {
    if (!proposal || !proposal.core || !proposal.proposal_hash || !board || !board.roster) return fail('args');
    const cls = DECISION_CLASSES[proposal.core.decision_class];
    if (!cls) return fail('unknown decision_class');
    // 1) re-derive + verify the proposal hash and proposer seal against the roster
    const coreBytes = utf8ToBytes(canon(proposalCore(proposal.core)));
    if (proposalHash(coreBytes) !== proposal.proposal_hash) return fail('proposal hash mismatch (tamper)');
    const proposer = board.roster[proposal.core.proposer_id];
    if (!proposer) return fail('proposer not on board');
    const pv = openSeal(coreBytes, proposal.proposer_seal, { trusted: pinsOf(proposer), requireKinds: reqKinds(proposer), requireDistinctLegs: true });
    if (!pv.verified) return fail('proposer seal invalid');
    // 2) eligible voter set for this class
    const eligible = cls.of === 'emergency' ? new Set(board.emergency_ids) : new Set(board.member_ids);
    // 3) verify each ballot, dedupe by member
    const seen = new Map(); const invalidBallots = []; const doubleVoters = [];
    for (let i = 0; i < (ballots || []).length; i++) {
      const b = ballots[i];
      if (!b || !b.core || b.core.proposal_hash !== proposal.proposal_hash) { invalidBallots.push({ i, why: 'not bound to this proposal' }); continue; }
      const mid = b.core.member_id;
      if (!eligible.has(mid)) { invalidBallots.push({ i, why: 'member not eligible for class ' + proposal.core.decision_class }); continue; }
      const entry = board.roster[mid];
      const bcoreBytes = utf8ToBytes(canon(ballotCore(b.core)));
      const bv = openSeal(bcoreBytes, b.ballot_seal, { trusted: pinsOf(entry), requireKinds: reqKinds(entry), requireDistinctLegs: true });
      if (!bv.verified) { invalidBallots.push({ i, why: 'ballot seal invalid' }); continue; }
      if (seen.has(mid)) {
        // a second, DIFFERENT ballot from the same member = double-vote attempt → flag + do NOT count either as approval
        if (seen.get(mid).choice !== b.core.choice || seen.get(mid).nonce !== b.core.nonce) doubleVoters.push(mid);
        continue;
      }
      seen.set(mid, { choice: b.core.choice, nonce: b.core.nonce });
    }
    // 4) count — a member flagged as double-voter is excluded entirely (their intent is ambiguous → fail-closed)
    let approvals = 0, rejections = 0;
    for (const [mid, v] of seen) { if (doubleVoters.includes(mid)) continue; if (v.choice === 'approve') approvals++; else if (v.choice === 'reject') rejections++; }
    // 5) time-lock
    const timeLocked = proposal.core.execute_after != null && Number.isFinite(opts.now) ? opts.now < proposal.core.execute_after
      : (proposal.core.execute_after != null && !Number.isFinite(opts.now) ? true : false); // execute_after set but no clock → treat as locked (fail-closed)
    const met = approvals >= cls.threshold;
    const executable = met && !timeLocked && doubleVoters.length === 0;
    return {
      class: proposal.core.decision_class, threshold: cls.threshold, of: cls.of, eligible: [...eligible].length,
      approvals, rejections, executable, timeLocked,
      reason: executable ? 'threshold met' : (!met ? `insufficient approvals (${approvals}/${cls.threshold})` : (timeLocked ? 'time-locked' : (doubleVoters.length ? 'double-vote detected' : 'not executable'))),
      invalidBallots, doubleVoters,
    };
  } catch { return fail('exception'); }
}

/** canTransition(from, to) — lifecycle guard (draft→review→vote→executed→archived / →rejected→archived). */
export function canTransition(from, to) { return !!LIFECYCLE_NEXT[from] && LIFECYCLE_NEXT[from].includes(to); }

/**
 * proposePause(reason, executor, { ts }) — an emergency 2-of-3 pause proposal (decision_class 'emergency', ≤72h).
 * The pause is only VALID (verifyPause) if ≥2 emergency-council ballots approve; expiry = ts + PAUSE_MAX_MS.
 */
export function proposePause(reason, proposer, { ts } = {}) {
  return propose({ proposalId: 'pause-' + (ts ?? '') + '-' + proposer.id, decisionClass: 'emergency', action: 'EMERGENCY_PAUSE', payloadHash: bytesToHex(sha256(utf8ToBytes(String(reason)))), createdTs: ts, executeAfter: null }, proposer);
}
/** verifyPause(proposal, ballots, board, { now }) — { paused, until, ... }; paused iff 2-of-3 emergency approvals AND now<expiry. */
export function verifyPause(proposal, ballots, board, { now } = {}) {
  const t = tally(proposal, ballots, board, { now });
  const started = proposal.core.created_ts;
  const until = Number.isFinite(started) ? started + PAUSE_MAX_MS : null;
  const withinWindow = until != null && Number.isFinite(now) ? now < until : (until != null ? true : false);
  return { paused: t.class === 'emergency' && t.approvals >= 2 && withinWindow, approvals: t.approvals, until, tally: t };
}

/* ---------- TOKEN-HOLDER governance — GATED (securities/token; not implemented) ---------- */
/** tokenHolderVote() — the blueprint's "67% token-holder approval / quadratic voting" needs a token; a token is a
 *  securities/regulatory matter (excluded from the current design). Board M-of-N threshold governance above is complete
 *  and token-free. This gate is machine-enforced: it always throws. */
export function tokenHolderVote() {
  throw new Error('OMEGA_TOKEN_GOVERNANCE_GATED: token-holder / quadratic voting requires a token (securities/regulatory matter, excluded). Use board M-of-N threshold governance (propose/castBallot/tally), which is token-free and complete.');
}

/* ---------------------------------------- self-test: node omega-gov.mjs ---------------------------------------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { slh_dsa_sha2_256f } = await import('@noble/post-quantum/slh-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n, len = 32) => new Uint8Array(len).fill(n);
  const mkMember = (id, n, withSlh = false) => ({
    id, ed: (() => { const sk = seed(n); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })(),
    mldsa: ml_dsa87.keygen(seed(n + 1)),
    ...(withSlh ? { slh: slh_dsa_sha2_256f.keygen(seed(n + 2, 96)) } : {}),
  });
  const M = [mkMember('alice', 10), mkMember('bob', 20), mkMember('carol', 30, true), mkMember('dave', 40), mkMember('erin', 50)];
  const board = createBoard({ members: M, emergencyCouncil: ['alice', 'bob', 'carol'] });
  ok(board.size === 5 && board.emergency_ids.length === 3, 'createBoard: 5 board / 3 emergency');

  // strategic (3-of-5): 3 approvals → executable
  const p = propose({ proposalId: 'p1', decisionClass: 'strategic', action: 'partner_with_qbeat', payloadHash: 'ab'.repeat(32), createdTs: 1000 }, M[0]);
  const ballots = [castBallot(p, M[0], 'approve', { ts: 1001 }), castBallot(p, M[1], 'approve', { ts: 1002 }), castBallot(p, M[2], 'approve', { ts: 1003 })];
  const t = tally(p, ballots, board, { now: 2000 });
  ok(t.executable && t.approvals === 3 && t.threshold === 3, 'tally: 3-of-5 strategic executable');

  // only 2 approvals → NOT executable (needs 3)
  ok(!tally(p, ballots.slice(0, 2), board, { now: 2000 }).executable, 'tally: 2/3 not executable');

  // forged ballot (signed by a non-board key) → rejected
  const outsider = mkMember('mallory', 90);
  const forged = castBallot(p, outsider, 'approve', { ts: 1004 });
  const t2 = tally(p, [...ballots.slice(0, 2), forged], board, { now: 2000 });
  ok(!t2.executable && t2.invalidBallots.length === 1, 'tally: outsider ballot rejected (not on roster/eligible)');

  // tampered ballot choice → seal fails
  const tampered = JSON.parse(JSON.stringify(ballots[0])); tampered.core.choice = 'reject';
  const t3 = tally(p, [tampered, ballots[1], ballots[2]], board, { now: 2000 });
  ok(t3.invalidBallots.some((x) => x.why.includes('seal')), 'tally: tampered ballot choice rejected');

  // ballot replayed onto a DIFFERENT proposal → not bound
  const p2 = propose({ proposalId: 'p2', decisionClass: 'operational', action: 'x', createdTs: 1000 }, M[0]);
  const t4 = tally(p2, [ballots[0]], board, { now: 2000 });
  ok(t4.invalidBallots.length === 1 && t4.approvals === 0, 'tally: ballot for p1 not counted on p2');

  // double-vote (same member, two different ballots) → flagged + excluded
  const b0b = castBallot(p, M[0], 'reject', { ts: 1005 });
  const t5 = tally(p, [ballots[0], b0b, ballots[1], ballots[2]], board, { now: 2000 });
  ok(t5.doubleVoters.includes('alice') && !t5.executable, 'tally: double-vote flagged + blocks execution');

  // constitutional needs 4 — 3 approvals not enough
  const pc = propose({ proposalId: 'pc', decisionClass: 'constitutional', action: 'amend', createdTs: 1000 }, M[0]);
  const cb = [M[0], M[1], M[2]].map((m) => castBallot(pc, m, 'approve', { ts: 1001 }));
  ok(!tally(pc, cb, board, { now: 2000 }).executable, 'tally: constitutional 3/4 not executable');
  cb.push(castBallot(pc, M[3], 'approve', { ts: 1001 }));
  ok(tally(pc, cb, board, { now: 2000 }).executable, 'tally: constitutional 4/4 executable');

  // time-lock: execute_after in the future → locked
  const pt = propose({ proposalId: 'pt', decisionClass: 'operational', action: 'x', createdTs: 1000, executeAfter: 5000 }, M[0]);
  const tb = [castBallot(pt, M[0], 'approve', { ts: 1001 }), castBallot(pt, M[1], 'approve', { ts: 1001 })];
  ok(!tally(pt, tb, board, { now: 2000 }).executable && tally(pt, tb, board, { now: 6000 }).executable, 'tally: time-lock enforced');
  ok(!tally(pt, tb, board, {}).executable, 'tally: execute_after set but no clock → locked (fail-closed)');

  // emergency pause: 2-of-3 emergency council
  const pause = proposePause('key compromise', M[0], { ts: 1000 });
  const pballots = [castBallot(pause, M[0], 'approve', { ts: 1001 }), castBallot(pause, M[1], 'approve', { ts: 1002 })];
  const pv = verifyPause(pause, pballots, board, { now: 1000 + 3600 * 1000 });
  ok(pv.paused && pv.until === 1000 + PAUSE_MAX_MS, 'pause: 2-of-3 emergency pause valid within 72h');
  ok(!verifyPause(pause, pballots, board, { now: 1000 + PAUSE_MAX_MS + 1 }).paused, 'pause: expires after 72h');
  // a non-emergency member cannot form the pause quorum
  const pballots2 = [castBallot(pause, M[0], 'approve', { ts: 1001 }), castBallot(pause, M[3], 'approve', { ts: 1002 })];
  ok(!verifyPause(pause, pballots2, board, { now: 1000 }).paused, 'pause: non-council member does not count toward 2-of-3');

  // lifecycle guard
  ok(canTransition('draft', 'review') && canTransition('vote', 'executed') && !canTransition('draft', 'executed') && !canTransition('archived', 'vote'), 'lifecycle: legal transitions only');

  // token-holder governance gate
  let gated = false; try { tokenHolderVote(); } catch (e) { gated = /TOKEN_GOVERNANCE_GATED/.test(e.message); }
  ok(gated, 'token-holder governance is securities-gated (throws)');

  console.log(`\nomega-gov self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
