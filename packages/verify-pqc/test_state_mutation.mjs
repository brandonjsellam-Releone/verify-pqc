import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

// Direct access to internal state for testing
const S_getter = () => {
  // We can't directly access S, so let's instrument handleRequest to log state
  console.log('Testing if state is properly mutated...');
};

// Instead, let's create a more detailed test that watches for the specific failure mode
handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('\n=== Testing state mutation on receive ===');

// Alice sends message 1
console.log('Step 1: Alice sends msg1 to Bob');
const msg1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'msg1' })));
console.log('  Sent, ciphertext bytes:', msg1.ciphertext_bytes);

// Bob replies WITHOUT reading (this is the critical test)
console.log('\nStep 2: Bob sends reply1 WITHOUT reading Alice msg (state should be un-advanced)');
try {
  const reply1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'reply1' })));
  console.log('  ERROR: Bob was able to send without reading! This should have failed.');
  console.log('  Reply sent:', reply1.delivered);
} catch (e) {
  console.log('  EXPECTED: Bob cannot send because bobState.CKs is null (no sending chain yet)');
  console.log('  Error:', e.message);
}

// Now Bob reads Alice's message (this should populate bobState.CKs)
console.log('\nStep 3: Bob reads Alice msg (this should seed bobState with CKs)');
const bob_inbox = json(handleRequest('GET', '/api/inbox/bob', ''));
console.log('  Bob got', bob_inbox.messages.length, 'messages, ok:', bob_inbox.messages[0]?.decrypted_ok);

// Now Bob tries again
console.log('\nStep 4: Bob sends reply1 AFTER reading (should now work)');
const reply1b = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'reply1' })));
console.log('  Bob→Alice sent:', reply1b.delivered);

// Verify Alice can decrypt
console.log('\nStep 5: Alice reads Bob reply');
const alice_inbox = json(handleRequest('GET', '/api/inbox/alice', ''));
console.log('  Alice got', alice_inbox.messages.length, 'messages');
console.log('  Message ok:', alice_inbox.messages[0]?.decrypted_ok);
console.log('  Message text:', alice_inbox.messages[0]?.text);
