import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('=== BOB INITIATES FIRST (reverse order) ===\n');

// BOB initiates instead of ALICE
console.log('Step 1: Bob sends msg to Alice (Bob is the INITIATOR now)');
const msg1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'hello alice' })));
console.log('  Sent:', msg1.delivered);

// Alice replies
console.log('\nStep 2: Alice sends reply (Alice is now RESPONDER)');
try {
  const reply = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'hi bob' })));
  console.log('  Sent:', reply.delivered);
  
  // Verify both can decrypt
  console.log('\nStep 3: Bob reads Alice reply');
  const bob_inbox = json(handleRequest('GET', '/api/inbox/bob', ''));
  console.log('  Bob inbox:', bob_inbox.messages.length, 'messages');
  bob_inbox.messages.forEach((m, i) => {
    console.log(`    [${i}] from=${m.from} ok=${m.decrypted_ok} text="${m.text}"`);
  });
  
  console.log('\nStep 4: Alice reads Bob initial message');
  const alice_inbox = json(handleRequest('GET', '/api/inbox/alice', ''));
  console.log('  Alice inbox:', alice_inbox.messages.length, 'messages');
  alice_inbox.messages.forEach((m, i) => {
    console.log(`    [${i}] from=${m.from} ok=${m.decrypted_ok} text="${m.text}"`);
  });
} catch (e) {
  console.log('  ERROR:', e.message);
}
