// crypto-handler.mjs — Main-thread crypto dispatcher.
//
// Listens for requests from the Worker via SharedArrayBuffer, performs async
// SubtleCrypto operations, and writes results back. The Worker blocks on
// Atomics.wait() while this handler performs async crypto.
//
// SharedArrayBuffer layout (see protocol.mjs for constants).

import {
  STATUS_IDLE,
  STATUS_REQUEST,
  STATUS_RESPONSE,
  STATUS_ERROR,
  CTRL_BYTES,
  INPUT_OFFSET,
  OUTPUT_OFFSET,
  OFF_STATUS,
  OFF_OP_ID,
  OFF_INPUT1_LEN,
  OFF_INPUT2_LEN,
  OFF_SCALAR,
  OFF_RESULT_LEN,
  OFF_EXTRA,
  OP_RANDOM_BYTES,
  OP_AES_GCM_ENCRYPT,
  OP_AES_GCM_DECRYPT,
  OP_HMAC_SHA256,
  OP_RSA_OAEP_SHA1_ENCRYPT,
  OP_RSA_OAEP_SHA1_DECRYPT,
  OP_RSA_GENERATE_KEYPAIR,
} from './protocol.mjs';

// PEM helpers — SubtleCrypto takes DER (SPKI / PKCS8), not PEM.
function pemToDer(pem) {
  const lines = pem.split('\n').filter(l => !l.startsWith('-----'));
  const b64 = lines.join('');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function derToPem(der, label) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  const lines = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export class CryptoHandler {
  constructor(sab) {
    this._sab = sab;
    this._ctrl = new Int32Array(sab, 0, CTRL_BYTES / 4);
    this._data = new Uint8Array(sab, CTRL_BYTES);
    this._running = false;
  }

  start() {
    this._running = true;
    this._poll();
  }

  stop() {
    this._running = false;
  }

  async _poll() {
    while (this._running) {
      // Wait for the Worker to set STATUS_REQUEST.
      const result = Atomics.waitAsync(this._ctrl, OFF_STATUS / 4, STATUS_IDLE);
      if (result.async) {
        await result.value;
      }
      if (!this._running) break;

      const status = Atomics.load(this._ctrl, OFF_STATUS / 4);
      if (status !== STATUS_REQUEST) continue;

      try {
        await this._dispatch();
      } catch (err) {
        this._writeError(err.message || 'unknown error');
      }
    }
  }

  async _dispatch() {
    const opId = this._ctrl[OFF_OP_ID / 4];
    const in1Len = this._ctrl[OFF_INPUT1_LEN / 4];
    const in2Len = this._ctrl[OFF_INPUT2_LEN / 4];
    const scalar = this._ctrl[OFF_SCALAR / 4];

    const in1 = in1Len > 0 ? this._data.slice(INPUT_OFFSET - CTRL_BYTES, INPUT_OFFSET - CTRL_BYTES + in1Len) : null;
    const in2 = in2Len > 0 ? this._data.slice(INPUT_OFFSET - CTRL_BYTES + in1Len, INPUT_OFFSET - CTRL_BYTES + in1Len + in2Len) : null;

    let result;

    switch (opId) {
      case OP_RANDOM_BYTES:
        result = this._randomBytes(scalar);
        break;
      case OP_AES_GCM_ENCRYPT:
        result = await this._aesGcmEncrypt(in1, in2);
        break;
      case OP_AES_GCM_DECRYPT:
        result = await this._aesGcmDecrypt(in1, in2);
        break;
      case OP_HMAC_SHA256:
        result = await this._hmacSha256(in1, in2);
        break;
      case OP_RSA_OAEP_SHA1_ENCRYPT:
        result = await this._rsaOaepEncrypt(in1, in2);
        break;
      case OP_RSA_OAEP_SHA1_DECRYPT:
        result = await this._rsaOaepDecrypt(in1, in2);
        break;
      case OP_RSA_GENERATE_KEYPAIR:
        result = await this._rsaGenerateKeypair(scalar);
        break;
      default:
        throw new Error(`unknown operation: ${opId}`);
    }

    this._writeResponse(result);
  }

  _randomBytes(n) {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return buf;
  }

  async _aesGcmEncrypt(keyBytes, plaintext) {
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    // SubtleCrypto returns [ciphertext || tag(16)]
    const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext || new Uint8Array(0));
    // Prepend nonce: [nonce(12) || ciphertext || tag(16)]
    const result = new Uint8Array(12 + ctBuf.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ctBuf), 12);
    return result;
  }

  async _aesGcmDecrypt(keyBytes, ciphertext) {
    if (ciphertext.byteLength < 28) throw new Error('ciphertext too short for AES-GCM');
    const iv = ciphertext.slice(0, 12);
    const ct = ciphertext.slice(12); // [ciphertext || tag(16)]
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct);
    return new Uint8Array(ptBuf);
  }

  async _hmacSha256(keyBytes, data) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data || new Uint8Array(0));
    return new Uint8Array(sig);
  }

  async _rsaOaepEncrypt(pubPemBytes, plaintext) {
    const pem = new TextDecoder().decode(pubPemBytes);
    const der = pemToDer(pem);
    const key = await crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['encrypt']);
    const ct = await crypto.subtle.encrypt('RSA-OAEP', key, plaintext || new Uint8Array(0));
    return new Uint8Array(ct);
  }

  async _rsaOaepDecrypt(privPemBytes, ciphertext) {
    const pem = new TextDecoder().decode(privPemBytes);
    const der = pemToDer(pem);
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt('RSA-OAEP', key, ciphertext);
    return new Uint8Array(pt);
  }

  async _rsaGenerateKeypair(bits) {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
      true,
      ['encrypt', 'decrypt'],
    );
    const privDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const pubDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privPem = derToPem(privDer, 'PRIVATE KEY');
    const pubPem = derToPem(pubDer, 'PUBLIC KEY');
    const privBytes = new TextEncoder().encode(privPem);
    const pubBytes = new TextEncoder().encode(pubPem);
    // Pack both into result: privPEM || pubPEM
    // Store pubLen in OFF_EXTRA so Worker can split them.
    const combined = new Uint8Array(privBytes.length + pubBytes.length);
    combined.set(privBytes, 0);
    combined.set(pubBytes, privBytes.length);
    // Store priv length in OFF_EXTRA for the Worker to split.
    this._ctrl[OFF_EXTRA / 4] = privBytes.length;
    return combined;
  }

  _writeResponse(result) {
    const outOffset = OUTPUT_OFFSET - CTRL_BYTES;
    this._data.set(result, outOffset);
    this._ctrl[OFF_RESULT_LEN / 4] = result.byteLength;
    Atomics.store(this._ctrl, OFF_STATUS / 4, STATUS_RESPONSE);
    Atomics.notify(this._ctrl, OFF_STATUS / 4);
  }

  _writeError(msg) {
    const encoded = new TextEncoder().encode(msg);
    const outOffset = OUTPUT_OFFSET - CTRL_BYTES;
    this._data.set(encoded, outOffset);
    this._ctrl[OFF_RESULT_LEN / 4] = encoded.byteLength;
    Atomics.store(this._ctrl, OFF_STATUS / 4, STATUS_ERROR);
    Atomics.notify(this._ctrl, OFF_STATUS / 4);
  }
}
