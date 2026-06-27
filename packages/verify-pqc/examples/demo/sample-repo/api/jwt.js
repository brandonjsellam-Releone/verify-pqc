// JWT verification using an RSA signature alg — quantum-broken; plan ML-DSA-87 (hybrid).
import jwt from 'jsonwebtoken';
export const verify = (token, key) => jwt.verify(token, key, { algorithms: ['RS256'] });
