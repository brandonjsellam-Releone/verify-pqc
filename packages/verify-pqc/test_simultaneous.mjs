import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('=== Edge case: Both parties send without reading first ===\n');

console.log('Step 1: Alice sends message 1');
handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'a1' }));
console.log('  Conversation created with ensureConversation("alice", "bob")');
console.log('  stateOf = { alice: aliceState, bob: bobState }');
console.log('  Alice uses stateOf["alice"] to send (has CKs)\n');

console.log('Step 2: Bob sends reply WITHOUT reading Alice msg first');
console.log('  sendMessage("bob", "alice")');
console.log('  ensureConversation("bob", "alice") retrieves SAME conversation');
console.log('  applyInbound("bob") finds Alice msg and processes it');
console.log('  ratchetReceive(stateOf["bob"], ...) advances bobState');
console.log('  ratchetSend(stateOf["bob"], ...) sends with advanced state\n');

try {
  const s = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'b1' })));
  console.log('  Result: Send succeeded\n');
  
  // Verify
  const bi = json(handleRequest('GET', '/api/inbox/bob', ''));
  const ai = json(handleRequest('GET', '/api/inbox/alice', ''));
  
  console.log('Final state:');
  console.log('  Bob inbox:', bi.messages.map(m => `"${m.text}"`).join(', '), '- ok:', bi.messages.every(m => m.decrypted_ok));
  console.log('  Alice inbox:', ai.messages.map(m => `"${m.text}"`).join(', '), '- ok:', ai.messages.every(m => m.decrypted_ok));
} catch (e) {
  console.log('  Result: Error -', e.message);
}

// Now test a different pattern: Bob initiates, THEN Alice tries to send before Bob reads
console.log('\n=== Alternative: Bob initiates, Alice replies before Bob reads ===\n');

handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('Step 1: Bob sends message 1');
handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'b1' }));
console.log('  Conversation created with ensureConversation("bob", "alice")');
console.log('  stateOf = { bob: aliceState_role, alice: bobState_role }\n');

console.log('Step 2: Alice sends reply WITHOUT Bob reading first');
console.log('  sendMessage("alice", "bob")');
console.log('  ensureConversation("alice", "bob") retrieves SAME conversation');
console.log('  applyInbound("alice") finds Bob msg and processes it');
console.log('  ratchetReceive(stateOf["alice"], ...) advances bobState_role');
console.log('  ratchetSend(stateOf["alice"], ...) sends with advanced state\n');

try {
  const s = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'a1' })));
  console.log('  Result: Send succeeded\n');
  
  // Verify
  const bi = json(handleRequest('GET', '/api/inbox/bob', ''));
  const ai = json(handleRequest('GET', '/api/inbox/alice', ''));
  
  console.log('Final state:');
  console.log('  Bob inbox:', bi.messages.map(m => `"${m.text}"`).join(', '), '- ok:', bi.messages.every(m => m.decrypted_ok));
  console.log('  Alice inbox:', ai.messages.map(m => `"${m.text}"`).join(', '), '- ok:', ai.messages.every(m => m.decrypted_ok));
} catch (e) {
  console.log('  Result: Error -', e.message);
}
