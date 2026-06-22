/*!
 * @trelyan/verify-pqc — dependency-free toolkit to inspect Falcon-1024 signatures and
 * verify post-quantum inscriptions on Algorand (AVM falcon_verify). MIT. Node + browser.
 *
 * Honest framing: 0xBA = standard Falcon-1024 compressed header 0x3A (high-nibble
 * compressed, low-nibble logn 10) OR'd with a 0x80 bit + a 0x00 version byte that are
 * trelyan-pq's deterministic-WRAPPER convention — NOT NIST Round-3 Falcon or FIPS-206
 * fields. This library reports bytes; it does not assert a standard that doesn't exist.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.verifyPQC = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var LOGN_1024 = 10, PUBKEY_LEN_1024 = 1793, SALT_LEN = 40;
  var DET_FLAG = 0x80, FORMAT_MASK = 0x70, FMT_COMPRESSED = 0x30, FMT_PADDED = 0x50, LOGN_MASK = 0x0f;

  function b64ToBytes(b64) {
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
    var s = atob(b64), u = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }
  function bytesToHex(u) { var h = ''; for (var i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0'); return h; }

  // Strip an Algorand ABI dynamic byte[] 2-byte big-endian length prefix, if present.
  // On-chain app-args are ABI-encoded; the opcode receives the DECODED value.
  function abiDecodeBytes(b) {
    if (b.length >= 2) { var d = (b[0] << 8) | b[1]; if (d === b.length - 2) return b.slice(2); }
    return b;
  }

  // Parse a Falcon-1024 signature's wire structure.
  function inspectFalconSig(sig) {
    if (!sig || !sig.length) throw new Error('empty signature');
    var h = sig[0], logn = h & LOGN_MASK, deterministic = !!(h & DET_FLAG), fmtBits = h & FORMAT_MASK;
    var fmt = fmtBits === FMT_COMPRESSED ? 'compressed' : fmtBits === FMT_PADDED ? 'padded' : 'unknown(0x' + fmtBits.toString(16) + ')';
    var saltPresent = fmt === 'compressed' && !deterministic;
    var overhead = 1 + (saltPresent ? SALT_LEN : 0), notes = [];
    if (logn !== LOGN_1024) notes.push('logn=' + logn + ' (expected 10 for Falcon-1024)');
    if (h === 0xBA) notes.push('0xBA = 0x3A|0x80: standard compressed Falcon-1024 (0x3A) + trelyan-pq deterministic-wrapper bit (0x80); the 0x80 and a 0x00 version byte are a project convention, NOT a NIST/FIPS-206 field');
    else if (h === 0x3A) notes.push('0x3A = standard compressed Falcon-1024 (NIST Round-3), randomized');
    return {
      totalLen: sig.length, headerHex: '0x' + h.toString(16).padStart(2, '0'),
      logn: logn, deterministic: deterministic, fmt: fmt, saltPresent: saltPresent,
      bodyLen: sig.length - overhead, notes: notes.join('; ') || 'ok'
    };
  }

  // Diff two signatures; for deterministic signers over the SAME (key,message) a conformant
  // pair MUST be byte-identical. Localizes the first divergence to header/salt/body.
  function compareSigs(a, b) {
    var ia = inspectFalconSig(a), ib = inspectFalconSig(b), n = Math.min(a.length, b.length), first = null;
    for (var i = 0; i < n; i++) { if (a[i] !== b[i]) { first = i; break; } }
    var region = first === null ? (a.length === b.length ? null : 'length')
      : first === 0 ? 'header'
      : (ia.saltPresent && first >= 1 && first < 1 + SALT_LEN) ? 'salt' : 'body';
    var identical = first === null && a.length === b.length, summary;
    if (identical) summary = 'IDENTICAL — byte-compatible for this vector.';
    else {
      var bits = [];
      if (ia.headerHex !== ib.headerHex) bits.push('header ' + ia.headerHex + ' vs ' + ib.headerHex);
      if (ia.saltPresent !== ib.saltPresent) bits.push('salt handling differs');
      if (a.length !== b.length) bits.push('length ' + a.length + ' vs ' + b.length);
      bits.push('first diff at offset ' + first + ' in the ' + region + ' region');
      summary = 'DIVERGE — ' + bits.join('; ');
    }
    return { identical: identical, lenA: a.length, lenB: b.length, firstDiffOffset: first, diffRegion: region, summary: summary };
  }

  // Verify an Algorand app's post-quantum inscription straight from a public indexer.
  // NOTE: trusts the single indexer you point at; it does not re-run falcon_verify locally.
  // The write-once `i_` box is the contract's own proof that falcon_verify accepted the sig.
  async function verifyOnChain(appId, opts) {
    opts = opts || {};
    var indexer = (opts.indexer || 'https://testnet-idx.algonode.cloud').replace(/\/$/, '');
    var f = opts.fetch || (typeof fetch !== 'undefined' ? fetch : null);
    if (!f) throw new Error('no fetch available; pass opts.fetch (Node <18) or run in a browser');
    var tr = await f(indexer + '/v2/transactions?application-id=' + encodeURIComponent(appId) + '&limit=100').then(function (r) { return r.json(); });
    var sig = null, sigInfo = null, sigTxid = null, sigRound = null, pubkey = false, pubTxid = null;
    (tr.transactions || []).forEach(function (t) {
      var at = t['application-transaction'] || {};
      (at['application-args'] || []).map(b64ToBytes).map(abiDecodeBytes).forEach(function (a) {
        if (!sig && a.length > 600 && a.length < 1500 && (a[0] & LOGN_MASK) === LOGN_1024) {
          sig = a; sigInfo = inspectFalconSig(a); sigTxid = t.id; sigRound = t['confirmed-round'];
        }
        if (a.length === PUBKEY_LEN_1024 && (a[0] & LOGN_MASK) === LOGN_1024) { pubkey = true; pubTxid = t.id; }
      });
    });
    var boxes = [];
    try {
      var bx = await f(indexer + '/v2/applications/' + encodeURIComponent(appId) + '/boxes?limit=100').then(function (r) { return r.json(); });
      boxes = (bx.boxes || []).map(function (b) { return b64ToBytes(b.name); });
    } catch (e) { /* boxes optional */ }
    var inscription = boxes.some(function (n) { return n.length >= 2 && n[0] === 0x69 && n[1] === 0x5f; }); // "i_"
    // Only recognized TRELYAN contracts gate their i_ box on falcon_verify. App-ids are
    // chain-assigned and unforgeable, so a box / Falcon-shaped arg on ANY OTHER app proves
    // nothing about falcon_verify — the "verified" verdict is gated on this set.
    var recognizedApps = (opts.recognizedApps || ['763809096', '764917520']).map(String);
    var recognized = recognizedApps.indexOf(String(appId)) !== -1;
    var verified = !!(sigInfo && sigInfo.fmt === 'compressed' && sigInfo.logn === 10 && inscription && recognized);
    return {
      appId: String(appId), indexer: indexer, verified: verified, recognized: recognized,
      signature: sigInfo, signatureHex: sig ? bytesToHex(sig) : null,
      sigTxid: sigTxid, sigRound: sigRound, pubkey: pubkey, pubkeyTxid: pubTxid,
      inscriptionBox: inscription, boxCount: boxes.length,
      claim: verified
        ? 'App ' + appId + ' is a recognized TRELYAN inscription contract with a Falcon-1024 signature and a write-once box (written only after falcon_verify passes), so the opcode accepted this signature.'
        : (inscription && !recognized
          ? 'App ' + appId + ' has an i_ box and a Falcon-shaped arg, but it is NOT a recognized TRELYAN contract — on an arbitrary app a box does not imply falcon_verify ran, so this is self-reported, not verified.'
          : (sigInfo
            ? 'A Falcon-1024 signature is on chain, but no write-once inscription box on a recognized app confirms the verify path ran.'
            : 'No Falcon-1024 signature found in the last 100 application calls.')),
      disclaimer: 'Reflects one indexer\'s view of Algorand TestNet; unaudited. "verified" requires a recognized TRELYAN app-id (' + recognizedApps.join(', ') + '). 0xBA is trelyan-pq\'s deterministic-wrapper convention, not a NIST/FIPS field.'
    };
  }

  return {
    abiDecodeBytes: abiDecodeBytes, inspectFalconSig: inspectFalconSig, compareSigs: compareSigs,
    verifyOnChain: verifyOnChain, b64ToBytes: b64ToBytes, bytesToHex: bytesToHex,
    constants: { LOGN_1024: LOGN_1024, PUBKEY_LEN_1024: PUBKEY_LEN_1024, SALT_LEN: SALT_LEN, DET_FLAG: DET_FLAG }
  };
});
