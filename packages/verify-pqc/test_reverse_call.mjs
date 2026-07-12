import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('=== CRITICAL TEST: What if ensureConversation is called with REVERSED args? ===\n');

// Send alice → bob (creates conversation with ensureConversation('alice', 'bob'))
console.log('Step 1: Alice sends to Bob');
handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'msg1' }));
console.log('  Conversation created via ensureConversation("alice", "bob")');
console.log('  convKey("alice", "bob") = ["alice", "bob"].sort().join("\x1f") = "alice\x1fbob"');
console.log('  stateOf = { alice: aliceState, bob: bobState }');

// Now hypothetically, if Bob calls ensureConversation('bob', 'alice'), what happens?
console.log('\nStep 2: If Bob called sendMessage("bob", "alice") ...');
console.log('  ensureConversation("bob", "alice") is called');
console.log('  convKey("bob", "alice") = ["bob", "alice"].sort().join("\x1f") = "alice\x1fbob"  <-- SAME KEY!');
console.log('  S.conversations.has(k) = true, so it RETURNS the existing conversation');
console.log('  But then applyInbound("bob") looks for messages in bob\'s mailbox');
console.log('  It processes alice→bob messages and calls:');
console.log('    ratchetReceive(stateOf["bob"], message)  where stateOf["bob"] = bobState');
console.log('  Then sendMessage would call:');
console.log('    ratchetSend(stateOf["bob"], text)  where stateOf["bob"] is NOW ADVANCED by DH-ratchet');

console.log('\nStep 3: Actually test this flow:');
const msg1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'from_alice' })));
console.log('  Alice sent (unread by Bob yet)');

// Now Bob sends BEFORE reading (applyInbound will read Alice's msg then Bob will send)
const msg2 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'from_bob' })));
console.log('  Bob sent (applyInbound would have advanced bobState)');

// Check what happened
const bob_inbox = json(handleRequest('GET', '/api/inbox/bob', ''));
const alice_inbox = json(handleRequest('GET', '/api/inbox/alice', ''));
console.log('\nResults:');
console.log('  Bob inbox:', bob_inbox.messages.map(m => `${m.from}:"${m.text}"`).join(', '));
console.log('  Alice inbox:', alice_inbox.messages.map(m => `${m.from}:"${m.text}"`).join(', '));
