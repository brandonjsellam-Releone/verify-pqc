/*!
 * pqdelegate — ThrondarAgent capability-DELEGATION engine (reference, DRAFT). Multi-agent orchestration trust over
 * pqcap: a coordinator agent that holds a capability can sub-delegate an ATTENUATED capability to a worker agent,
 * which can delegate further — and a tool gateway verifies the whole chain back to the root principal before acting.
 *
 * THE HARD PROPERTY — ATTENUATION (a delegation may only NARROW, never widen). Enforced three ways, so a worker can
 * never escalate beyond what its coordinator was granted:
 *   1. CAVEAT ACCUMULATION (Macaroon-style): the request is checked against the root's caveats AND every delegation's
 *      added caveats — the conjunction. A child can ADD constraints; it can never remove/loosen a parent's, because
 *      the parent's caveat is still evaluated. (A "looser" child caveat is simply harmless — the tighter parent binds.)
 *   2. TOOL / SCOPE / USE NARROWING: tool ⊑ parent ('*' parent → any child; else equal); `scope` may only be
 *      inherited/kept (or set when the parent is unconstrained null/'*'), never switched or broadened; `max_uses`
 *      cannot exceed a bounded parent's nor go unbounded. (Cross-REQUEST use COUNTING is the gateway's job via a
 *      durable ledger — pqdelegate enforces the declared NARROWING; the gateway meters actual uses, like pqcap.)
 *   3. DELEGATION-AUTHORITY CHAIN: each delegation is hybrid-signed by the PREVIOUS link's grantee (only the holder
 *      can sub-delegate) and binds parent_ref = hash(parent core) (no splicing/reordering onto another chain).
 * Plus: expiry conjunction (now < every link's expiry); leaf holder proof-of-possession (only the final delegatee can
 * wield the chain); TOTAL/fail-closed verification.
 *
 * HONEST SCOPE: authorization only — a verified chain says "the root principal's authority reached this leaf agent for
 * this request, attenuated at every hop". It does not execute anything; the gateway does, after verifying. pqcap
 * authorizes one hop; pqdelegate authorizes the chain; pqauditlog records what was then done. Unaudited reference.
 * Self-test: node pqdelegate.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { makeAgentId, evalCaveats, verifyCapability } from './pqcap.mjs';

const DELEG_CTX = utf8ToBytes('trelyan-agent-delegation-v1');         // delegation signing domain (Ed25519 + ML-DSA)
const DELEG_SLH_CTX = utf8ToBytes('trelyan-agent-delegation-slh-v1'); // distinct domain for the optional SLH leg
const DELEG_POP_CTX = utf8ToBytes('trelyan-agent-delegation-pop-v1'); // distinct domain for the leaf holder PoP

function canon(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
const h = (s) => bytesToHex(sha256(utf8ToBytes(s)));

// replicate pqcap.capCore so linkRef(rootCapability) is computable from the token (binds the SAME bytes pqcap signs).
const capCoreReplica = (t) => ({ v: '1', issuer: t.issuer, agent: t.agent, tool: t.tool, caveats: t.caveats, scope: t.scope ?? null, nonce: t.nonce, issued_at: t.issued_at ?? null, expires_at: t.expires_at ?? null, max_uses: t.max_uses ?? null, audience: t.audience ?? null });
const delegationCore = (d) => ({ v: '1', parent_ref: d.parent_ref, delegator: d.delegator, delegatee: d.delegatee, tool: d.tool, added_caveats: d.added_caveats ?? {}, scope: d.scope ?? null, nonce: d.nonce, issued_at: d.issued_at ?? null, expires_at: d.expires_at ?? null, max_uses: d.max_uses ?? null, audience: d.audience ?? null });
const isDelegation = (x) => !!(x && typeof x === 'object' && x.delegator !== undefined);
const linkRef = (link) => h(canon(isDelegation(link) ? delegationCore(link) : capCoreReplica(link)));
const granteeId = (link) => (isDelegation(link) ? link.delegatee : link.agent);
const grantePub = (link) => (isDelegation(link) ? link.delegatee_pub : link.agent_pub);
// tool attenuation: child ⊑ parent. parent '*' permits any child; otherwise the child must keep the exact tool.
const toolAttenuates = (parentTool, childTool) => parentTool === '*' || childTool === parentTool;
const loadPub = (o) => ({ ed: hexToBytes(o.ed), mldsa: hexToBytes(o.mldsa), ...(o.slh ? { slh: hexToBytes(o.slh) } : {}) });

// delegatorKeys = the holder of `parent` (its grantee) { ed, mldsa[, slh] }. delegatee = the next agent's pubkeys.
// tool must be ⊑ parent.tool. addedCaveats = extra least-privilege constraints (see pqcap.evalCaveats). expiresAt/
// maxUses/audience may only tighten in effect (the chain enforces the conjunction at verify).
export function delegate({ delegatorKeys, parent, delegatee, tool, addedCaveats, scope, nonce, issuedAt, expiresAt, maxUses, audience }) {
  if (!delegatorKeys || !delegatorKeys.ed || !delegatorKeys.mldsa) throw new Error('delegatorKeys must be { ed, mldsa[, slh] }');
  if (!parent || typeof parent !== 'object') throw new Error('parent (root capability or delegation) is required');
  if (!delegatee || !delegatee.ed || !delegatee.mldsa) throw new Error('delegatee must be pubkeys { ed, mldsa[, slh] }');
  if (makeAgentId(delegatorKeys) !== granteeId(parent)) throw new Error('delegator is not the grantee of the parent (only the holder may sub-delegate)');
  const parentTool = parent.tool;
  const childTool = tool != null ? String(tool) : parentTool;
  if (!toolAttenuates(parentTool, childTool)) throw new Error('tool widening forbidden: child tool "' + childTool + '" not ⊑ parent tool "' + parentTool + '"');
  // scope attenuation (council fix): inherit/keep, or set only when the parent is unconstrained — never switch/broaden.
  const parentScope = parent.scope ?? null;
  const childScope = scope !== undefined ? (scope ?? null) : parentScope;
  if (parentScope != null && parentScope !== '*' && childScope !== parentScope) throw new Error('scope widening forbidden: child scope must equal the parent scope (or the parent must be unconstrained)');
  // max_uses attenuation (council fix): a bounded parent caps the child — it cannot exceed it nor go unbounded.
  const parentMax = parent.max_uses ?? null;
  if (parentMax != null && (maxUses == null || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > parentMax)) throw new Error('max_uses widening forbidden: a bounded parent (' + parentMax + ') requires a child max_uses that is a positive integer ≤ ' + parentMax);
  const core = delegationCore({ parent_ref: linkRef(parent), delegator: makeAgentId(delegatorKeys), delegatee: makeAgentId(delegatee),
    tool: childTool, added_caveats: addedCaveats || {}, scope: childScope, nonce: String(nonce ?? bytesToHex(randomBytes(16))),
    issued_at: issuedAt ?? null, expires_at: expiresAt ?? null, max_uses: maxUses ?? null, audience: audience ?? null });
  const coreBytes = utf8ToBytes(canon(core));
  const link = { ...core,
    delegator_pub: { ed: bytesToHex(_pub(delegatorKeys.ed)), mldsa: bytesToHex(_pub(delegatorKeys.mldsa)) },
    delegatee_pub: { ed: bytesToHex(_pub(delegatee.ed)), mldsa: bytesToHex(_pub(delegatee.mldsa)) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(DELEG_CTX, coreBytes), delegatorKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, delegatorKeys.mldsa.secretKey, { context: DELEG_CTX })) };
  if (delegatee.slh) link.delegatee_pub.slh = bytesToHex(_pub(delegatee.slh));
  if (delegatorKeys.slh) { link.delegator_pub.slh = bytesToHex(_pub(delegatorKeys.slh)); link.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, delegatorKeys.slh.secretKey, { context: DELEG_SLH_CTX })); }
  return link;
}

// the final delegatee proves possession of its keys over a fresh, request-bound challenge.
export function proveLeafHolder(agentKeys, challenge) {
  const msg = concatBytes(DELEG_POP_CTX, utf8ToBytes(String(challenge)));
  const p = { challenge: String(challenge), ed_sig: bytesToHex(ed25519.sign(msg, agentKeys.ed.secretKey)), mldsa_sig: bytesToHex(ml_dsa87.sign(msg, agentKeys.mldsa.secretKey, { context: DELEG_POP_CTX })) };
  if (agentKeys.slh) p.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(msg, agentKeys.slh.secretKey, { context: DELEG_POP_CTX }));
  return p;
}

function verifyDelegSig(link, delegatorPub) {
  const coreBytes = utf8ToBytes(canon(delegationCore(link)));
  let edOk = false, pqOk = false, slhOk = true;
  try { edOk = ed25519.verify(hexToBytes(link.ed_sig), concatBytes(DELEG_CTX, coreBytes), delegatorPub.ed); } catch { edOk = false; }
  try { pqOk = ml_dsa87.verify(hexToBytes(link.mldsa_sig), coreBytes, delegatorPub.mldsa, { context: DELEG_CTX }); } catch { pqOk = false; }
  if (delegatorPub.slh) { try { slhOk = !!(link.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(link.slh_sig), coreBytes, delegatorPub.slh, { context: DELEG_SLH_CTX })); } catch { slhOk = false; } }
  return edOk && pqOk && slhOk;
}

// TOTAL / fail-closed. chain = [rootCapability(pqcap token), delegation, delegation, ...]. trustedRoot = pinned
// principal { ed, mldsa[, slh] }. opts: request {tool,args} (checked vs the ACCUMULATED caveats of every link),
// now, audience, requireHolderProof + challenge + holderProof (leaf PoP), requireSlhHolder.
export function verifyDelegationChain(chain, trustedRoot, opts = {}) {
  try {
    if (!Array.isArray(chain) || chain.length === 0) return { verified: false, reason: 'empty chain' };
    const root = chain[0];
    if (isDelegation(root)) return { verified: false, reason: 'chain[0] must be a root capability, not a delegation' };
    // 1) root capability: authentic under the pinned principal + its own caveats/tool/expiry/audience vs the request
    // allowUnmeteredCheck: pqdelegate verifies STRUCTURE + attenuation; cross-request use-counting of a max_uses root
    // is the gateway's durable-ledger job (pqcap.verifyAndConsume), not pqdelegate's — so don't fail-closed here.
    const rv = verifyCapability(root, trustedRoot, { request: opts.request, now: opts.now, audience: opts.audience, allowUnmeteredCheck: true });
    if (!rv.verified) return { verified: false, reason: 'root capability invalid: ' + (rv.reason || '') };
    let parent = root;
    let currentTool = root.tool;
    let currentGrantee = root.agent;
    let effMax = root.max_uses ?? null;
    for (let i = 1; i < chain.length; i++) {
      const d = chain[i];
      if (!isDelegation(d)) return { verified: false, reason: 'link ' + i + ' is not a delegation' };
      // delegator must be the previous link's grantee, and its embedded pub must hash to that id
      let dpub; try { dpub = loadPub(d.delegator_pub); } catch { return { verified: false, reason: 'bad delegator_pub at ' + i }; }
      if (makeAgentId(dpub) !== currentGrantee) return { verified: false, reason: 'delegation ' + i + ' not signed by the parent grantee' };
      if (d.delegator !== currentGrantee) return { verified: false, reason: 'delegator id != parent grantee at ' + i };
      // bind to THIS parent (no splicing onto another chain / reordering)
      if (d.parent_ref !== linkRef(parent)) return { verified: false, reason: 'parent_ref mismatch at ' + i + ' (spliced/reordered)' };
      // delegator signature over the delegation core
      if (!verifyDelegSig(d, dpub)) return { verified: false, reason: 'delegation signature invalid at ' + i };
      // embedded delegatee pub must hash to the signed delegatee id (no grantee substitution)
      let depub; try { depub = loadPub(d.delegatee_pub); } catch { return { verified: false, reason: 'bad delegatee_pub at ' + i }; }
      if (makeAgentId(depub) !== d.delegatee) return { verified: false, reason: 'delegatee_pub != signed delegatee id at ' + i };
      // ATTENUATION: tool ⊑ parent tool
      if (!toolAttenuates(currentTool, d.tool)) return { verified: false, reason: 'tool widening at ' + i };
      // ATTENUATION: scope + max_uses may only narrow (council fix — signed fields a child controls)
      { const ps = parent.scope ?? null; if (ps != null && ps !== '*' && (d.scope ?? null) !== ps) return { verified: false, reason: 'scope widening at ' + i }; }
      { const pm = parent.max_uses ?? null; if (pm != null && (d.max_uses == null || !Number.isInteger(d.max_uses) || d.max_uses < 1 || d.max_uses > pm)) return { verified: false, reason: 'max_uses widening at ' + i }; }
      if (d.max_uses != null) effMax = (effMax == null ? d.max_uses : Math.min(effMax, d.max_uses));
      // ATTENUATION: enforce this delegation's added caveats against the request (conjunction with all ancestors)
      if (opts.request !== undefined) {
        if (d.tool !== '*' && (opts.request || {}).tool !== d.tool) return { verified: false, reason: 'request tool not authorized at link ' + i };
        const cav = evalCaveats(d.added_caveats || {}, (opts.request || {}).args);
        if (!cav.ok) return { verified: false, reason: 'caveat at link ' + i + ': ' + cav.reason };
      }
      // expiry conjunction
      if (d.expires_at != null && opts.now != null && Number(opts.now) >= Number(d.expires_at)) return { verified: false, reason: 'delegation ' + i + ' expired' };
      if (d.audience != null && opts.audience !== d.audience) return { verified: false, reason: 'audience mismatch at ' + i };
      parent = d; currentTool = d.tool; currentGrantee = d.delegatee;
    }
    // leaf must match the request tool (most-narrowed)
    if (opts.request !== undefined && currentTool !== '*' && (opts.request || {}).tool !== currentTool) return { verified: false, reason: 'request tool != effective leaf tool' };
    // leaf holder proof-of-possession: only the final delegatee can wield the chain
    if (opts.requireHolderProof) {
      const leafPub = loadPub(grantePub(chain[chain.length - 1]));
      if (makeAgentId(leafPub) !== currentGrantee) return { verified: false, reason: 'leaf pub != effective grantee' };
      const pf = opts.holderProof;
      if (!pf || opts.challenge == null || pf.challenge !== String(opts.challenge)) return { verified: false, reason: 'leaf holder proof: missing / wrong challenge' };
      const msg = concatBytes(DELEG_POP_CTX, utf8ToBytes(String(opts.challenge)));
      let he = false, hp = false, hs = true;
      try { he = ed25519.verify(hexToBytes(pf.ed_sig), msg, leafPub.ed); } catch { he = false; }
      try { hp = ml_dsa87.verify(hexToBytes(pf.mldsa_sig), msg, leafPub.mldsa, { context: DELEG_POP_CTX }); } catch { hp = false; }
      if (opts.requireSlhHolder) { try { hs = !!(leafPub.slh && pf.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(pf.slh_sig), msg, leafPub.slh, { context: DELEG_POP_CTX })); } catch { hs = false; } }
      if (!he || !hp || !hs) return { verified: false, reason: 'leaf holder proof invalid' };
    }
    return { verified: true, root: root.issuer, leaf_agent: currentGrantee, tool: currentTool, max_uses: effMax, depth: chain.length - 1 };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqdelegate.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { issueCapability, makePrincipalId } = await import('./pqcap.mjs');
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const ks = (a, b) => ({ ed: ed(a), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(b)) });
  const pub = (k) => ({ ed: k.ed.publicKey, mldsa: k.mldsa.publicKey, ...(k.slh ? { slh: k.slh.publicKey } : {}) });
  const principal = ks(1, 2), A = ks(3, 4), B = ks(5, 6), C = ks(7, 8), attacker = ks(9, 10);
  const tRoot = pub(principal);

  // root: A may DatabaseQuery, op in {select,update}, limit ≤ 1000, audience orch, expiry 1000
  const root = issueCapability({ issuerKeys: principal, agent: pub(A), tool: 'DatabaseQuery',
    caveats: { arg_in: { op: ['select', 'update'] }, arg_max: { limit: 1000 } }, audience: 'orch', expiresAt: 1000, nonce: 'root-1' });
  // A → B: narrow to op select only, limit ≤ 100
  const dAB = delegate({ delegatorKeys: A, parent: root, delegatee: pub(B), tool: 'DatabaseQuery', addedCaveats: { arg_in: { op: ['select'] }, arg_max: { limit: 100 } }, audience: 'orch', expiresAt: 800, nonce: 'd-ab' });
  // B → C: narrow to public.* tables
  const dBC = delegate({ delegatorKeys: B, parent: dAB, delegatee: pub(C), tool: 'DatabaseQuery', addedCaveats: { arg_prefix: { table: 'public.' } }, audience: 'orch', expiresAt: 600, nonce: 'd-bc' });
  const chain = [root, dAB, dBC];
  const chal = 'req-7';
  const okReq = { tool: 'DatabaseQuery', args: { op: 'select', limit: 50, table: 'public.users' } };

  ok(verifyDelegationChain(chain, tRoot, { request: okReq, now: 1, audience: 'orch', requireHolderProof: true, challenge: chal, holderProof: proveLeafHolder(C, chal) }).verified === true, 'in-bounds request down a 2-hop chain verifies (with leaf PoP)');
  ok(verifyDelegationChain(chain, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }, { request: okReq, now: 1, audience: 'orch' }).verified === false, 'wrong pinned root principal → FAILS');

  // ATTENUATION via caveat accumulation
  ok(verifyDelegationChain(chain, tRoot, { request: { tool: 'DatabaseQuery', args: { op: 'update', limit: 50, table: 'public.x' } }, now: 1, audience: 'orch' }).verified === false, 'op=update allowed by ROOT but narrowed away by A→B → REJECTED (conjunction)');
  ok(verifyDelegationChain(chain, tRoot, { request: { tool: 'DatabaseQuery', args: { op: 'select', limit: 500, table: 'public.x' } }, now: 1, audience: 'orch' }).verified === false, 'limit 500 ≤ root 1000 but > A→B 100 → REJECTED (tighter child caveat binds)');
  ok(verifyDelegationChain(chain, tRoot, { request: { tool: 'DatabaseQuery', args: { op: 'select', limit: 50, table: 'secret.creds' } }, now: 1, audience: 'orch' }).verified === false, 'table outside public. (B→C) → REJECTED');

  // a LOOSER child caveat cannot widen: A→B with limit 100000, request 5000 → root 1000 still binds
  const dLoose = delegate({ delegatorKeys: A, parent: root, delegatee: pub(B), tool: 'DatabaseQuery', addedCaveats: { arg_max: { limit: 100000 } }, audience: 'orch', nonce: 'd-loose' });
  ok(verifyDelegationChain([root, dLoose], tRoot, { request: { tool: 'DatabaseQuery', args: { op: 'select', limit: 5000 } }, now: 1, audience: 'orch' }).verified === false, 'child tries to LOOSEN limit (100000) but root cap (1000) still binds → REJECTED (no widening)');

  // TOOL widening forbidden — at creation AND at verify
  let widenThrew = false; try { delegate({ delegatorKeys: A, parent: root, delegatee: pub(B), tool: 'CodeExecutor', nonce: 'd-widen' }); } catch { widenThrew = true; }
  ok(widenThrew, 'delegate() refuses to widen the tool (DatabaseQuery → CodeExecutor)');
  const dWiden = JSON.parse(JSON.stringify(dAB)); dWiden.tool = 'CodeExecutor'; // hand-forge (sig now stale)
  ok(verifyDelegationChain([root, dWiden], tRoot, { request: { tool: 'CodeExecutor', args: {} }, now: 1, audience: 'orch' }).verified === false, 'hand-forged tool-widening delegation → REJECTED (sig + attenuation)');

  // DELEGATION AUTHORITY: only the parent's grantee may sub-delegate. Build a delegation valid in the ATTACKER's OWN
  // chain, then try to splice it onto OUR root (whose grantee is A, not the attacker) → rejected at verify.
  const rootAtk = issueCapability({ issuerKeys: principal, agent: pub(attacker), tool: 'DatabaseQuery', caveats: {}, nonce: 'root-atk' });
  const dAtk = delegate({ delegatorKeys: attacker, parent: rootAtk, delegatee: pub(B), tool: 'DatabaseQuery', nonce: 'd-atk' });
  ok(verifyDelegationChain([root, dAtk], tRoot, { request: okReq, now: 1, audience: 'orch' }).verified === false, 'a delegation by a NON-grantee (attacker), valid only in its own chain, spliced onto our root → REJECTED');
  let authThrew = false; try { delegate({ delegatorKeys: attacker, parent: root, delegatee: pub(B), nonce: 'd-x' }); } catch { authThrew = true; }
  ok(authThrew, 'delegate() refuses a delegator that is not the parent grantee (create-time guard)');

  // SCOPE + MAX_USES attenuation (council fix — DeepSeek/OpenAI: signed fields a child controls must only narrow)
  const rootScoped = issueCapability({ issuerKeys: principal, agent: pub(A), tool: 'DatabaseQuery', caveats: {}, scope: 'tenant/acme/*', maxUses: 5, audience: 'orch', nonce: 'root-sc' });
  let scopeThrew = false; try { delegate({ delegatorKeys: A, parent: rootScoped, delegatee: pub(B), scope: 'tenant/*', maxUses: 5, audience: 'orch', nonce: 'd-sc' }); } catch { scopeThrew = true; }
  ok(scopeThrew, 'delegate() refuses to WIDEN scope (tenant/acme/* → tenant/*)');
  let useThrew = false; try { delegate({ delegatorKeys: A, parent: rootScoped, delegatee: pub(B), scope: 'tenant/acme/*', maxUses: 50, audience: 'orch', nonce: 'd-mu' }); } catch { useThrew = true; }
  ok(useThrew, 'delegate() refuses to WIDEN max_uses (parent 5 → child 50)');
  let unboundThrew = false; try { delegate({ delegatorKeys: A, parent: rootScoped, delegatee: pub(B), scope: 'tenant/acme/*', maxUses: null, audience: 'orch', nonce: 'd-ub' }); } catch { unboundThrew = true; }
  ok(unboundThrew, 'delegate() refuses to go UNBOUNDED under a bounded parent (max_uses 5 → null)');
  const dScopeWiden = JSON.parse(JSON.stringify(delegate({ delegatorKeys: A, parent: rootScoped, delegatee: pub(B), scope: 'tenant/acme/*', maxUses: 3, audience: 'orch', nonce: 'd-ok-sc' }))); dScopeWiden.scope = 'tenant/*';
  ok(verifyDelegationChain([rootScoped, dScopeWiden], tRoot, { request: { tool: 'DatabaseQuery', args: {} }, now: 1, audience: 'orch' }).verified === false, 'hand-forged scope-widening (sig stale) → REJECTED at verify');
  const dScopeOk = delegate({ delegatorKeys: A, parent: rootScoped, delegatee: pub(B), scope: 'tenant/acme/*', maxUses: 2, audience: 'orch', nonce: 'd-ok2' });
  const okScoped = verifyDelegationChain([rootScoped, dScopeOk], tRoot, { request: { tool: 'DatabaseQuery', args: {} }, now: 1, audience: 'orch' });
  ok(okScoped.verified === true && okScoped.max_uses === 2, 'a chain that keeps scope + narrows max_uses verifies (effective max_uses=2)');

  // parent_ref binding: splice / tamper
  const dSplice = JSON.parse(JSON.stringify(dBC)); dSplice.parent_ref = 'deadbeef';
  ok(verifyDelegationChain([root, dAB, dSplice], tRoot, { request: okReq, now: 1, audience: 'orch' }).verified === false, 'tampered parent_ref → REJECTED (no splicing)');
  ok(verifyDelegationChain([root, dBC], tRoot, { request: okReq, now: 1, audience: 'orch' }).verified === false, 'reordered chain (dBC without dAB) → parent_ref mismatch → REJECTED');

  // tamper an added caveat (re-sign-free) → delegator sig fails
  const dTam = JSON.parse(JSON.stringify(dAB)); dTam.added_caveats.arg_max.limit = 1000000;
  ok(verifyDelegationChain([root, dTam, dBC], tRoot, { request: okReq, now: 1, audience: 'orch' }).verified === false, 'tampered delegation caveat (re-sign-free) → signature FAILS');

  // leaf PoP: wrong holder, replay, missing
  ok(verifyDelegationChain(chain, tRoot, { request: okReq, now: 1, audience: 'orch', requireHolderProof: true, challenge: chal, holderProof: proveLeafHolder(attacker, chal) }).verified === false, 'leaf PoP by the WRONG keys → REJECTED');
  ok(verifyDelegationChain(chain, tRoot, { request: okReq, now: 1, audience: 'orch', requireHolderProof: true, challenge: 'other', holderProof: proveLeafHolder(C, chal) }).verified === false, 'leaf PoP challenge replay → REJECTED');
  ok(verifyDelegationChain(chain, tRoot, { request: okReq, now: 1, audience: 'orch', requireHolderProof: true }).verified === false, 'requireHolderProof with no proof → REJECTED');

  // expiry conjunction (leaf expires first)
  ok(verifyDelegationChain(chain, tRoot, { request: okReq, now: 700, audience: 'orch' }).verified === false, 'now=700 ≥ B→C expiry 600 → REJECTED (expiry conjunction)');

  // single-link chain (root only, no delegations) still works
  ok(verifyDelegationChain([root], tRoot, { request: { tool: 'DatabaseQuery', args: { op: 'update', limit: 900 } }, now: 1, audience: 'orch' }).verified === true, 'root-only chain verifies its own caveats (update allowed at root)');

  // 3-leg hybrid delegator
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(11));
  const A3 = { ed: A.ed, mldsa: A.mldsa, slh };
  // A3's agent id differs (slh changes the id) → issue a root to A3
  const root3 = issueCapability({ issuerKeys: principal, agent: pub(A3), tool: '*', caveats: {}, nonce: 'root3' });
  const d3 = delegate({ delegatorKeys: A3, parent: root3, delegatee: pub(B), tool: 'X', nonce: 'd3' });
  ok(typeof d3.slh_sig === 'string' && verifyDelegationChain([root3, d3], tRoot, { request: { tool: 'X', args: {} }, now: 1 }).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH) delegation verifies');
  const d3s = JSON.parse(JSON.stringify(d3)); d3s.slh_sig = '00';
  // A3 has slh, so its embedded delegator_pub.slh is checked → stripped leg fails
  ok(verifyDelegationChain([root3, d3s], tRoot, { request: { tool: 'X', args: {} }, now: 1 }).verified === false, 'stripped SLH leg on a 3-leg delegation → REJECTED (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, [], [42], [root, 42], [{ delegator: 'x' }]]) { try { if (verifyDelegationChain(bad, tRoot, { request: okReq, now: 1 }).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed chains → verified:false, never throws');

  console.log('pqdelegate self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqdelegate\.mjs$/.test(process.argv[1] || '')) selfTest();
