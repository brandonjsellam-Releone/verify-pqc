/*!
 * @trelyan/pq-sdk — unified post-quantum SDK surface (DRAFT, TRL ~5-6).
 *
 * One import for the TRELYAN Tier-1 PQ stack:
 *   - verifyPQC : Falcon-1024 inspection + on-chain (AVM falcon_verify) verification  [index.js, UMD]
 *   - pqef      : PQEF v0.1 evidence-bundle verifier (the open standard)              [pqef.mjs]
 *   - polarseek : PQ KMS / key-custody root (hybrid X25519+ML-KEM-1024 envelope)      [polarseek.mjs]
 *   - pqsign    : PQ code-signing + RFC-6962 transparency notary                       [pqsign.mjs]
 *
 * All built on @noble/post-quantum (ML-KEM-1024 / ML-DSA-87) + @noble/hashes/ciphers/curves.
 * Honest posture: hybrid-PQ, fail-closed, FIPS-203/204 algorithms (NOT a FIPS-140-3 validated
 * module — see TRELYAN_PQEF_SPEC §B1). Falcon = on-chain/provenance leg only (FIPS 206 in development).
 */
import * as pqef from './pqef.mjs';
import * as polarseek from './polarseek.mjs';
import * as pqsign from './pqsign.mjs';
import * as pqtransport from './pqtransport.mjs';
import * as pqanswer from './pqanswer.mjs';
import * as pqcouncil from './pqcouncil.mjs';
import * as pqguard from './pqguard.mjs';
import * as pqinduct from './pqinduct.mjs';
import * as pqmoa from './pqmoa.mjs';
import * as pqclaimgate from './pqclaimgate.mjs';
import * as pqverify from './pqverify.mjs';
import * as pqratchet from './pqratchet.mjs';
import * as pqindex from './pqindex.mjs';
import * as pqassistant from './pqassistant.mjs';
import * as pqcbom from './pqcbom.mjs';
import * as pqgateway from './pqgateway.mjs';
import * as pqratchetHE from './pqratchet-he.mjs';
import * as pqtsa from './pqtsa.mjs';
import * as pqgatewaySession from './pqgateway-session.mjs';
import * as pqkt from './pqkt.mjs';
import * as pqcbomReport from './pqcbom-report.mjs';
import * as pqverifyApi from './pqverify-api.mjs';
import * as pqpki from './pqpki.mjs';
import * as pqvault from './pqvault.mjs';
import * as pqcompliance from './pqcompliance.mjs';
import * as pqx3dh from './pqx3dh.mjs';
import * as pqmarket from './pqmarket.mjs';
import * as pqseal from './pqseal.mjs';
import * as pqattest from './pqattest.mjs';
import * as pqtrace from './pqtrace.mjs';
import * as pqeval from './pqeval.mjs';
import * as pqaibom from './pqaibom.mjs';
import * as pqgovernanceRecord from './pqgovernance-record.mjs';
import * as pqgovernanceGate from './pqgovernance-gate.mjs';
import * as pqgovernPolicy from './pqgovern-policy.mjs';
import * as pqgovernEvidence from './pqgovern-evidence.mjs';
import * as pqgovernAnchor from './pqgovern-anchor.mjs';
import * as pqgovernCli from './pqgovern-cli.mjs';
import * as qiv from './qiv.mjs';
import * as qivPin from './qiv-pin.mjs';
import * as omega from './omega.mjs';
import * as omegaGov from './omega-gov.mjs';
import * as omegaBridge from './omega-bridge.mjs';
import * as omegaEvidence from './omega-evidence.mjs';
import * as omegaChain from './omega-chain.mjs';
import * as omegaSentinel from './omega-sentinel.mjs';
import * as omegaNexus from './omega-nexus.mjs';
import * as omegaServer from './omega-server.mjs';
import * as pqmeshServer from './pqmesh-server.mjs';
import * as pqsearchServer from './pqsearch-server.mjs';
import * as trelyanConsole from './trelyan-console.mjs';
import * as crossProductE2E from './cross-product-e2e.mjs';
import * as demoGateway from './demo-gateway.mjs';
import * as apiServer from './api-server.mjs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const verifyPQC = require('./index.js');

export { pqef, polarseek, pqsign, pqtransport, pqanswer, pqcouncil, pqguard, pqinduct, pqmoa, pqclaimgate, pqverify, pqratchet, pqratchetHE, pqx3dh, pqindex, pqassistant, pqcbom, pqcbomReport, pqgateway, pqgatewaySession, pqtsa, pqkt, pqverifyApi, pqpki, pqvault, pqcompliance, pqmarket, pqseal, pqattest, pqtrace, pqaibom, pqeval, pqgovernanceRecord, pqgovernanceGate, pqgovernPolicy, pqgovernEvidence, pqgovernAnchor, pqgovernCli, qiv, qivPin, omega, omegaGov, omegaBridge, omegaEvidence, omegaChain, omegaSentinel, omegaNexus, omegaServer, pqmeshServer, pqsearchServer, trelyanConsole, crossProductE2E, demoGateway, apiServer, verifyPQC };
export const SDK_VERSION = '0.28.0-draft';
export const SUITES = {
  kem: 'X25519+ML-KEM-1024',
  signature: 'ML-DSA-87 (FIPS 204)',
  diversity: 'SLH-DSA-256s (FIPS 205)',
  agileSigning: 'pqseal — N-leg AND-composition (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519), crypto-agile + anti-downgrade',
  attestation: 'pqattest — seal ∧ threshold-timestamp ∧ transparency-log; seal countersigns the timestamp+STH (downgrade-detecting under its trust model)',
  onchain: 'Falcon-1024 (FIPS 206 in development — provenance only)',
  aead: 'AES-256-GCM',
};
export default { pqef, polarseek, pqsign, pqtransport, pqanswer, pqcouncil, pqguard, pqinduct, pqmoa, pqclaimgate, pqverify, pqratchet, pqratchetHE, pqx3dh, pqindex, pqassistant, pqcbom, pqcbomReport, pqgateway, pqgatewaySession, pqtsa, pqkt, pqverifyApi, pqpki, pqvault, pqcompliance, pqmarket, pqseal, pqattest, pqtrace, pqaibom, pqeval, pqgovernanceRecord, pqgovernanceGate, pqgovernPolicy, pqgovernEvidence, pqgovernAnchor, pqgovernCli, demoGateway, apiServer, verifyPQC, SDK_VERSION, SUITES };
