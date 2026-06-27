import { publishCapability, verifyListing, selectAgent, generateAgent } from './pqmarket.mjs';
import { PQTransparencyLog } from './pqsign.mjs';

const agent = generateAgent(new Uint8Array(32).fill(7));
const listing = publishCapability({ agent, capabilities: ['cap-x'], claims: {} }, { ts: 1, validFrom: 0, expiresAt: 1000 });

console.log('verifyListing expired WITH at=5000  :', verifyListing(listing, agent.publicKey, { at: 5000 }));
console.log('verifyListing expired NO at         :', verifyListing(listing, agent.publicKey, {}));
console.log('verifyListing expired NO opts arg   :', verifyListing(listing, agent.publicKey));

const log = new PQTransparencyLog();
const sel = selectAgent(listing, log, { trustedAgentPub: agent.publicKey, capability: 'cap-x', trustedReviewers: [], minDistinct: 0, maxDisputes: 0 });
console.log('selectAgent expired NO at accept    :', sel.accept, '| reason:', sel.reason);
