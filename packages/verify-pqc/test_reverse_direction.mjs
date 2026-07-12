import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('=== TEST: Does applyInbound correctly find reverse direction messages? ===\n');

// Step 1: Bob sends FIRST (Bob is initiator)
console.log('Step 1: Bob sends message to Alice');
console.log('  sendMessage("bob", "alice", "hello")');
console.log('    -> ensureConversation("bob", "alice")');
console.log('       -> convKey("bob", "alice") = convKey(sorted) = "alice\x1fbob"');
console.log('       -> establishSession(bob_identity, alice_identity, ...)');
console.log('          -> aliceState is Bob (because he is the initiator)');
console.log('          -> bobState is Alice (because she is the responder)');
console.log('       -> stateOf = { bob: aliceState, alice: bobState }');
console.log('    -> applyInbound("bob")');
console.log('       -> looks for messages in bob\'s mailbox (TO bob)');
console.log('       -> initially EMPTY');
console.log('    -> ratchetSend(stateOf["bob"], ...) uses aliceState (has CKs)');

const s1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'hello' })));
console.log('  -> Sent successfully\n');

// Step 2: Alice replies
console.log('Step 2: Alice sends reply');
console.log('  sendMessage("alice", "bob", "hi")');
console.log('    -> ensureConversation("alice", "bob")');
console.log('       -> convKey("alice", "bob") = "alice\x1fbob"');
console.log('       -> Conversation exists! Return it');
console.log('       -> stateOf is STILL { bob: aliceState, alice: bobState }');
console.log('    -> applyInbound("alice")');
console.log('       -> looks for messages in alice\'s mailbox (TO alice)');
console.log('       -> finds bob→alice message');
console.log('       -> convKey(bob, alice) = "alice\x1fbob"  (CORRECT, sorted!)');
console.log('       -> ratchetReceive(stateOf["alice"], ...) uses bobState');
console.log('          -> PROBLEM: bobState is the RESPONDER state (no sending chain yet)');
console.log('          -> ratchetReceive needs bobState to have DHr=null initially');
console.log('       -> After DH ratchet, bobState gets CKs');
console.log('    -> ratchetSend(stateOf["alice"], ...) now uses advanced bobState');

const s2 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'hi' })));
console.log('  -> Sent successfully\n');

// Verify
const bi = json(handleRequest('GET', '/api/inbox/bob', ''));
const ai = json(handleRequest('GET', '/api/inbox/alice', ''));
console.log('Results:');
console.log('  Bob inbox:', bi.messages.map(m => `${m.from}:"${m.text}" ok=${m.decrypted_ok}`).join('; '));
console.log('  Alice inbox:', ai.messages.map(m => `${m.from}:"${m.text}" ok=${m.decrypted_ok}`).join('; '));

// NOW THE CRITICAL CASE: What if BOTH bob and alice call sendMessage but 
// the conversation was initialized with the OPPOSITE direction?
console.log('\n=== EDGE CASE: stateOf uses REVERSED identity mapping ===');
handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('Scenario: What if ensureConversation("alice", "bob") vs ("bob", "alice")');
console.log('Both call ensureConversation at same time, which one wins?');
console.log('Or: one calls it, stores the conversation, the other retrieves but the');
console.log('stateOf keys are reversed?\n');

// Direct test: does applyInbound correctly look up stateOf[id]?
console.log('Testing if applyInbound correctly uses stateOf[id] regardless of direction:');

// Alice sends to Bob
console.log('\n  A→B: Alice sends');
const ab = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'from_a' })));

// Bob sends reply (this should call applyInbound("bob") which finds message TO bob,
// then uses convKey(alice, bob) to find conversation, then uses stateOf[bob])
console.log('  B→A: Bob sends');
const ba = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'from_b' })));

// Check if both can decrypt
const bob_final = json(handleRequest('GET', '/api/inbox/bob', ''));
const alice_final = json(handleRequest('GET', '/api/inbox/alice', ''));
console.log('\n  Bob decrypts:', bob_final.messages.length, 'msgs -', bob_final.messages.every(m => m.decrypted_ok) ? 'ALL OK' : 'SOME FAILED');
console.log('  Alice decrypts:', alice_final.messages.length, 'msgs -', alice_final.messages.every(m => m.decrypted_ok) ? 'ALL OK' : 'SOME FAILED');
