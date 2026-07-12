import { handleRequest } from './pqmesh-server.mjs';

const json = (r) => JSON.parse(r.body);

// The defect claim says: "Bob replies: retrieves same conv via same key, calls 
// ratchetSend(stateOf[bob]). But stateOf[bob] is initBob (CKs=null), now both use 
// same state for bidirectional send/receive without re-keying."

// For this to be true, we need:
// 1. stateOf[bob] to remain unadvanced (still CKs=null) when Bob tries to send
// 2. This would require applyInbound to NOT run, or to NOT find the message

console.log('=== Can we trigger the claimed defect? ===\n');

handleRequest('POST', '/api/reset', '{}');
handleRequest('POST', '/api/register', JSON.stringify({ id: 'alice' }));
handleRequest('POST', '/api/register', JSON.stringify({ id: 'bob' }));

console.log('Scenario: Alice sends, then Bob tries to reply');
console.log('For defect: Bob\'s send must skip applyInbound or applyInbound must fail\n');

// Alice sends
console.log('Step 1: Alice sends');
const s1 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'alice', to: 'bob', text: 'hello' })));
console.log('  Success\n');

// Now, the ONLY way applyInbound could fail to advance stateOf[bob]:
// 1. If applyInbound is not called (but it's always called on line 63)
// 2. If applyInbound finds no messages (but message is in mailbox)
// 3. If applyInbound finds the message but can't find the conversation (line 55)
// 4. If ratchetReceive is not called (but it's called on line 56)

console.log('Step 2: Bob tries to send WITHOUT reading');
console.log('  applyInbound("bob") is ALWAYS called first (line 63)');
console.log('  It should find alice→bob message in bob\'s mailbox');
console.log('  It should call convKey("alice", "bob") = "alice\x1fbob"');
console.log('  This key was created by Alice, so conversation exists');
console.log('  ratchetReceive(stateOf["bob"], ...) should advance stateOf["bob"]');
console.log('  Then ratchetSend(stateOf["bob"], ...) should work with advanced state\n');

const s2 = json(handleRequest('POST', '/api/send', JSON.stringify({ from: 'bob', to: 'alice', text: 'hi' })));
console.log('  Send result:', s2.delivered ? 'SUCCESS' : 'FAILED');

// If there WAS a defect where both used the same state, we would see:
// - Both using initBob state (CKs=null) and getting an error on first send
// - Or both using aliceState and ratcheting the same way (wrong re-keying)
// - Or successful send but then decryption fails because the ratchet wasn't advanced

const bi = json(handleRequest('GET', '/api/inbox/bob', ''));
const ai = json(handleRequest('GET', '/api/inbox/alice', ''));

console.log('\nVerification:');
console.log('  Bob can decrypt Alice msg:', bi.messages[0]?.decrypted_ok ? 'YES' : 'NO');
console.log('  Alice can decrypt Bob msg:', ai.messages[0]?.decrypted_ok ? 'YES' : 'NO');

if (bi.messages[0]?.decrypted_ok && ai.messages[0]?.decrypted_ok) {
  console.log('\nDefect NOT PRESENT: Both messages decrypt correctly');
  console.log('  This means:');
  console.log('    - Alice used aliceState (with CKs) to send msg1');
  console.log('    - Bob read msg1 via ratchetReceive(stateOf["bob"], msg1)');
  console.log('    - stateOf["bob"] was advanced with new DHs and CKs');
  console.log('    - Bob used advanced stateOf["bob"] to send reply');
  console.log('    - Alice used aliceState (with new DHr) to decrypt reply');
} else {
  console.log('\nDefect MIGHT BE PRESENT: Decryption failed');
  console.log('  But let\'s check why...');
}
