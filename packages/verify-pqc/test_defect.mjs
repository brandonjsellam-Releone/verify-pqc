import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

// Reset
handleRequest('POST', '/api/reset', '{}');

// Register both
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

// Alice sends first message
console.log('=== Alice sends to Bob ===');
const s1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'msg1' })));
console.log('Alice→Bob sent:', s1.delivered);

// Bob checks his inbox (processes Alice's message via applyInbound)
console.log('\n=== Bob reads inbox ===');
const bi1 = json(handleRequest('GET', '/api/inbox/bob', ''));
console.log('Bob inbox:', bi1.messages.length, 'messages, decrypted ok:', bi1.messages[0]?.decrypted_ok);

// Now Bob sends a reply
console.log('\n=== Bob replies to Alice ===');
try {
  const reply = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'reply1' })));
  console.log('Bob→Alice sent:', reply.delivered);
} catch (e) {
  console.log('ERROR on Bob send:', e.message);
}

// Alice reads the reply
console.log('\n=== Alice reads reply ===');
const ai1 = json(handleRequest('GET', '/api/inbox/alice', ''));
console.log('Alice inbox:', ai1.messages.length, 'messages');
if (ai1.messages.length > 0) {
  console.log('  - from:', ai1.messages[0].from);
  console.log('  - decrypted ok:', ai1.messages[0].decrypted_ok);
  console.log('  - text:', ai1.messages[0].text);
}

console.log('\n=== Testing bidirectional: both send before reading ===');
handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

// Alice initiates
handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'a1' }));
handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'a2' }));

console.log('Alice sent 2 messages to Bob (unread)');

// Bob tries to send BEFORE reading Alice's messages
try {
  const s2 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'b1' })));
  console.log('Bob sent reply (before draining):', s2.delivered);
  
  // Verify both can decrypt
  const bob_inbox = json(handleRequest('GET', '/api/inbox/bob', ''));
  console.log('\nBob receives Alice messages:');
  bob_inbox.messages.forEach((m, i) => {
    console.log(`  [${i}] ok=${m.decrypted_ok} text="${m.text}"`);
  });
  
  const alice_inbox = json(handleRequest('GET', '/api/inbox/alice', ''));
  console.log('\nAlice receives Bob reply:');
  alice_inbox.messages.forEach((m, i) => {
    console.log(`  [${i}] ok=${m.decrypted_ok} text="${m.text}"`);
  });
} catch (e) {
  console.log('ERROR:', e.message);
}
