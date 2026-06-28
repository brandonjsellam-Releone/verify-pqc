// intentionally vulnerable fixture for the action self-test
const h = crypto.createHash("md5");
const kp = RSA.generateKeyPair(2048);
const sig = ECDSA.sign(msg, "secp256k1");
