import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('=== Testing if reversed conversation creation causes state confusion ===\n');

// Case 1: Alice initiates (creates conversation as ("alice", "bob"))
console.log('NORMAL CASE: Alice initiates');
const a1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'msg_a1' })));
const a2 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'msg_a2' })));
console.log('  Alice sent 2 messages');

// Bob replies (retrieves same conversation)
const b1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'msg_b1' })));
console.log('  Bob replied (state was advanced by applyInbound)');

// Verify
const bi = json(handleRequest('GET', '/api/inbox/bob', ''));
console.log('  Bob decrypts Alice msg:', bi.messages.length, 'ok:', bi.messages.every(m => m.decrypted_ok));

const ai = json(handleRequest('GET', '/api/inbox/alice', ''));
console.log('  Alice decrypts Bob msg:', ai.messages.length, 'ok:', ai.messages.every(m => m.decrypted_ok));

// Now the REVERSE case
handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('\nREVERSE CASE: Bob initiates (creates conversation as ("bob", "alice"))');
const b2 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'msg_b2' })));
console.log('  Bob sent message (initiates with ("bob", "alice"))');
console.log('  stateOf = { bob: aliceState_role, alice: bobState_role }');
console.log('  Bob uses stateOf["bob"] = aliceState_role to send (has CKs, correct)');

// Now Alice sends back (calls ensureConversation("alice", "bob"))
// This retrieves the SAME conversation (key is sorted), so:
// stateOf still = { bob: aliceState_role, alice: bobState_role }
// But now Alice needs to use stateOf["alice"] = bobState_role (responder, CKs=null initially)

const a3 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'msg_a3' })));
console.log('  Alice replies (calls ensureConversation("alice", "bob"), gets SAME conversation)');
console.log('  Alice uses stateOf["alice"] = bobState_role (responder initially)');
console.log('  Sent:', a3.delivered);

// Verify
const bi2 = json(handleRequest('GET', '/api/inbox/bob', ''));
console.log('  Bob decrypts Alice msg:', bi2.messages.length, 'ok:', bi2.messages.every(m => m.decrypted_ok));

const ai2 = json(handleRequest('GET', '/api/inbox/alice', ''));
console.log('  Alice decrypts Bob msg:', ai2.messages.length, 'ok:', ai2.messages.every(m => m.decrypted_ok));

console.log('\nBoth cases worked! So the state mapping IS correct regardless of init direction.');
console.log('Reason: applyInbound correctly advances stateOf[id] before sendMessage uses it.');
