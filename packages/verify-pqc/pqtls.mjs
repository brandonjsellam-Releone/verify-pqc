/*!
 * pqtls — raw TLS 1.3 KEX-group prober (reference, DRAFT). Reads the supported-group a server SELECTS/REQUESTS directly
 * off the wire, because Node's public API (`getEphemeralKeyInfo()`) returns {} for TLS 1.3 and cannot tell us the group.
 *
 * HOW: send a minimal ClientHello that lists ML-KEM hybrid groups FIRST in supported_groups but provides a key_share for
 * X25519 only. A server that supports/prefers a PQ group it has no key_share for replies with a HelloRetryRequest whose
 * key_share names that PQ group (e.g. X25519MLKEM768 = 0x11EC) — revealing PQ-KEX support; a classical-only server just
 * completes a ServerHello on X25519. Either way the key_share extension's first 2 bytes = the selected/requested group.
 *
 * HONEST SCOPE: this is a single-round, read-only probe — it does NOT complete the handshake, decrypt anything, or read
 * the certificate (the cert is encrypted in TLS 1.3; the auth leg is read separately via node:tls in pqposture). It
 * reports the group the server selects GIVEN this specific offer (PQ-first, classical key_share); a fuller scan would
 * enumerate every offered group. Dependency-light: node:net + @noble/curves (x25519) + @noble/hashes (randomBytes).
 * Self-test (offline): node pqtls.mjs   ·   Live: PQC_LIVE_PROBE=1 node pqtls.mjs cloudflare.com
 */
import net from 'node:net';
import { x25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';

// IANA TLS Supported Groups (code -> { name, pq }). PQ = ML-KEM hybrid (or legacy Kyber draft).
export const GROUPS = {
  0x001d: { name: 'X25519', pq: false }, 0x0017: { name: 'secp256r1', pq: false },
  0x0018: { name: 'secp384r1', pq: false }, 0x0019: { name: 'secp521r1', pq: false },
  0x0100: { name: 'ffdhe2048', pq: false }, 0x0101: { name: 'ffdhe3072', pq: false },
  0x11ec: { name: 'X25519MLKEM768', pq: true }, 0x11eb: { name: 'SecP256r1MLKEM768', pq: true },
  0x11ed: { name: 'SecP384r1MLKEM1024', pq: true },
  0x6399: { name: 'X25519Kyber768Draft00', pq: true }, 0x639a: { name: 'SecP256r1Kyber768Draft00', pq: true },
};
// SHA-256("HelloRetryRequest") — the special ServerHello.random that marks an HRR (RFC 8446 §4.1.3).
const HRR_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex');

const u16 = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
const u24 = (n) => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
const ext = (type, data) => Buffer.concat([u16(type), u16(data.length), data]);

// build a TLS 1.3 ClientHello record offering PQ groups first, with an X25519 key_share. x25519Pub: 32-byte Uint8Array.
export function buildClientHello(host, x25519Pub) {
  const rand = Buffer.from(randomBytes(32));
  const sid = Buffer.from(randomBytes(32));
  const cipherSuites = Buffer.concat([u16(0x1301), u16(0x1302), u16(0x1303)]);          // AES-128/256-GCM, ChaCha20
  const groupCodes = [0x11ec, 0x6399, 0x001d, 0x0017];                                  // ML-KEM hybrids FIRST, then classical
  const supportedGroups = ext(0x000a, Buffer.concat([u16(groupCodes.length * 2), ...groupCodes.map(u16)]));
  const sigCodes = [0x0403, 0x0804, 0x0805, 0x0806, 0x0401, 0x0807];                    // ECDSA-P256, RSA-PSS, RSA-PKCS1, Ed25519
  const sigAlgs = ext(0x000d, Buffer.concat([u16(sigCodes.length * 2), ...sigCodes.map(u16)]));
  const supportedVersions = ext(0x002b, Buffer.concat([Buffer.from([2]), u16(0x0304)]));// TLS 1.3
  const ksEntry = Buffer.concat([u16(0x001d), u16(32), Buffer.from(x25519Pub)]);        // key_share: X25519 only
  const keyShare = ext(0x0033, Buffer.concat([u16(ksEntry.length), ksEntry]));
  const hb = Buffer.from(String(host), 'ascii');
  const sni = ext(0x0000, Buffer.concat([u16(hb.length + 3), Buffer.from([0x00]), u16(hb.length), hb]));
  const exts = Buffer.concat([sni, supportedGroups, sigAlgs, supportedVersions, keyShare]);
  const body = Buffer.concat([u16(0x0303), rand, Buffer.from([sid.length]), sid,
    u16(cipherSuites.length), cipherSuites, Buffer.from([0x01, 0x00]), u16(exts.length), exts]);
  const hs = Buffer.concat([Buffer.from([0x01]), u24(body.length), body]);              // ClientHello handshake msg
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), u16(hs.length), hs]);          // handshake record
}

// parse the server's first record: pull the selected/requested group from the ServerHello/HRR key_share extension.
export function parseSelectedGroup(buf) {
  try {
    if (!buf || buf.length < 5) return { error: 'short response' };
    const type = buf[0];
    if (type === 21) return { error: 'TLS alert (likely handshake_failure / no shared group)' };
    if (type !== 22) return { error: 'not a handshake record (type ' + type + ')' };
    const recLen = buf.readUInt16BE(3);
    const hs = buf.subarray(5, 5 + recLen);
    if (hs.length < 4 || hs[0] !== 2) return { error: 'not a ServerHello (msg ' + (hs[0]) + ')' };
    let p = 4 + 2;                                  // skip handshake header(4) + legacy_version(2)
    const random = hs.subarray(p, p + 32); p += 32;
    const is_hrr = Buffer.compare(random, HRR_RANDOM) === 0;
    const sidLen = hs[p]; p += 1 + sidLen;          // legacy_session_id_echo
    p += 2 + 1;                                     // cipher_suite(2) + legacy_compression(1)
    const extLen = hs.readUInt16BE(p); p += 2;
    const extEnd = Math.min(p + extLen, hs.length);
    while (p + 4 <= extEnd) {
      const etype = hs.readUInt16BE(p), elen = hs.readUInt16BE(p + 2), edata = hs.subarray(p + 4, p + 4 + elen);
      if (etype === 0x0033 && edata.length >= 2) {  // key_share (SH: group||key_exchange; HRR: group only)
        const code = edata.readUInt16BE(0);
        const g = GROUPS[code] || { name: '0x' + code.toString(16), pq: null };
        return { group_code: code, group_name: g.name, pq: g.pq, is_hrr };
      }
      p += 4 + elen;
    }
    return { error: 'no key_share extension in response', is_hrr };
  } catch (e) { return { error: 'parse: ' + e.message }; }
}

// probe a host: open a raw TCP socket, send the ClientHello, parse the first response record. Resolves to the parse result.
export function probeKexGroup(host, port = 443, opts = {}) {
  return new Promise((resolve) => {
    let done = false; const chunks = [];
    const finish = (o) => { if (!done) { done = true; try { sock.destroy(); } catch { /* noop */ } resolve(o); } };
    const pub = x25519.getPublicKey(randomBytes(32));
    const ch = buildClientHello(host, pub);
    const sock = net.connect({ host, port }, () => sock.write(ch));
    sock.on('data', (d) => {
      chunks.push(d); const buf = Buffer.concat(chunks);
      if (buf.length >= 5 && buf.length >= 5 + buf.readUInt16BE(3)) finish(parseSelectedGroup(buf));
    });
    sock.setTimeout(opts.timeout || 8000, () => finish({ error: 'timeout' }));
    sock.on('error', (e) => finish({ error: e.message }));
    sock.on('end', () => { const buf = Buffer.concat(chunks); finish(buf.length ? parseSelectedGroup(buf) : { error: 'no data' }); });
  });
}

/* ---------- self-test (offline) + optional live probe ---------- */
// build a minimal synthetic ServerHello/HRR record carrying a key_share for `groupCode` (for offline parser testing).
function fakeServerHello(groupCode, hrr) {
  const random = hrr ? HRR_RANDOM : Buffer.from(randomBytes(32));
  const ks = ext(0x0033, hrr ? u16(groupCode) : Buffer.concat([u16(groupCode), u16(32), Buffer.alloc(32, 7)]));
  const sv = ext(0x002b, u16(0x0304));
  const exts = Buffer.concat([sv, ks]);
  const body = Buffer.concat([u16(0x0303), random, Buffer.from([0]), u16(0x1301), Buffer.from([0]), u16(exts.length), exts]);
  const hs = Buffer.concat([Buffer.from([0x02]), u24(body.length), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), u16(hs.length), hs]);
}

async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  // ClientHello shape
  const ch = buildClientHello('example.com', x25519.getPublicKey(randomBytes(32)));
  ok(ch[0] === 0x16 && ch[1] === 0x03 && ch[2] === 0x01, 'ClientHello is a handshake record (0x16 0x03 0x01)');
  ok(ch.readUInt16BE(3) === ch.length - 5, 'record length header matches payload');
  ok(ch[5] === 0x01, 'handshake msg_type = ClientHello (0x01)');
  ok(ch.includes(Buffer.from([0x11, 0xec])) && ch.includes(Buffer.from([0x00, 0x33])), 'offers X25519MLKEM768 (0x11ec) + has a key_share ext (0x0033)');
  // parse a synthetic ServerHello selecting a PQ group
  const pqSH = parseSelectedGroup(fakeServerHello(0x11ec, false));
  ok(pqSH.group_code === 0x11ec && pqSH.group_name === 'X25519MLKEM768' && pqSH.pq === true && pqSH.is_hrr === false, 'parses a ServerHello key_share -> X25519MLKEM768 (pq:true)');
  // parse a synthetic HRR requesting a PQ group
  const pqHRR = parseSelectedGroup(fakeServerHello(0x11ec, true));
  ok(pqHRR.group_code === 0x11ec && pqHRR.pq === true && pqHRR.is_hrr === true, 'parses a HelloRetryRequest -> requested group X25519MLKEM768, is_hrr:true');
  // classical selection
  const clSH = parseSelectedGroup(fakeServerHello(0x001d, false));
  ok(clSH.group_name === 'X25519' && clSH.pq === false, 'parses a classical X25519 selection (pq:false)');
  // unknown group -> pq:null (honest), name hex
  const unk = parseSelectedGroup(fakeServerHello(0xabcd, false));
  ok(unk.group_code === 0xabcd && unk.pq === null && /0xabcd/.test(unk.group_name), 'unknown group -> pq:null (honest), hex name');
  // malformed / alert -> fail-closed error (never throws)
  ok(!!parseSelectedGroup(Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])).error, 'TLS alert record -> error (not a crash)');
  let total = true; for (const bad of [null, Buffer.alloc(0), Buffer.from([0x16]), Buffer.from([0x16, 3, 3, 0, 200])]) { try { if (!parseSelectedGroup(bad).error) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed responses -> {error}, never throws');

  if (process.env.PQC_LIVE_PROBE) {
    const host = process.argv[2] || 'cloudflare.com';
    const r = await probeKexGroup(host, 443, { timeout: 8000 });
    console.log('  LIVE ' + host + ': ' + (r.error ? 'error ' + r.error : (r.group_name + ' (pq:' + r.pq + ', hrr:' + r.is_hrr + ')')));
  }
  console.log('pqtls self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqtls\.mjs$/.test(process.argv[1] || '')) selfTest();
