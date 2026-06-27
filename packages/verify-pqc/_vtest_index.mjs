import { buildSignedShard, verifyShard } from './pqindex.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const attacker = ml_dsa87.keygen(new Uint8Array(32).fill(99));
const terms = [{ term: 'a', postings: [{ d: 1 }] }, { term: 'b', postings: [{ d: 2 }] }];
const shard = buildSignedShard({ term_range: ['a','z'], terms }, attacker.secretKey, attacker.publicKey, { ts: 1 });

console.log('verifyShard unpinned (no pin) :', JSON.stringify(verifyShard(shard)));
const good = ml_dsa87.keygen(new Uint8Array(32).fill(7));
console.log('verifyShard pinned to good    :', JSON.stringify(verifyShard(shard, good.publicKey).verified));
