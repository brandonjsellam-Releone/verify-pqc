// Synthetic demo file — intentionally vulnerable crypto so the scanner has something real to find.
const crypto = require('node-forge');
function makeKeys() {
  const kp = RSA.generateKeyPair(2048);          // quantum-broken (Shor)
  const sig = ECDSA.sign(message, 'secp256k1');  // quantum-broken (Shor)
  const fingerprint = MD5(certificate);          // classically broken
  return { kp, sig, fingerprint };
}
module.exports = { makeKeys };
