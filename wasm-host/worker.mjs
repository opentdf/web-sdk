// worker.mjs — Web Worker that loads the WASM TDF module and provides
// host function imports. Crypto operations bridge to the main thread via
// SharedArrayBuffer + Atomics (Worker blocks, main thread does async crypto).
//
// Messages IN:
//   { type: 'init', sab: SharedArrayBuffer, wasmUrl: string }
//   { type: 'encrypt', id, kasPubPEM, kasURL, attrs, plaintext, integrityAlg, segIntegrityAlg, segmentSize }
//
// Messages OUT:
//   { type: 'ready' }
//   { type: 'result', id, data: Uint8Array }
//   { type: 'error', id, message: string }

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
  ERR_SENTINEL,
} from './protocol.mjs';

let ctrl; // Int32Array over SAB control region
let data; // Uint8Array over SAB data region
let wasmInstance;
let wasmMemory;
let lastError = '';

// ── SharedArrayBuffer bridge ────────────────────────────────────────

// callHost sends a request to the main thread and blocks until it responds.
// Returns the result Uint8Array or throws on error.
function callHost(opId, input1, input2, scalar) {
  const in1 = input1 || new Uint8Array(0);
  const in2 = input2 || new Uint8Array(0);

  // Write inputs to data region
  const sabData = data;
  const in1Off = INPUT_OFFSET - CTRL_BYTES;
  sabData.set(in1, in1Off);
  sabData.set(in2, in1Off + in1.byteLength);

  // Write control params
  ctrl[OFF_OP_ID / 4] = opId;
  ctrl[OFF_INPUT1_LEN / 4] = in1.byteLength;
  ctrl[OFF_INPUT2_LEN / 4] = in2.byteLength;
  ctrl[OFF_SCALAR / 4] = scalar || 0;
  ctrl[OFF_RESULT_LEN / 4] = 0;
  ctrl[OFF_EXTRA / 4] = 0;

  // Signal request and block
  Atomics.store(ctrl, OFF_STATUS / 4, STATUS_REQUEST);
  Atomics.notify(ctrl, OFF_STATUS / 4);
  Atomics.wait(ctrl, OFF_STATUS / 4, STATUS_REQUEST);

  const status = Atomics.load(ctrl, OFF_STATUS / 4);
  const resultLen = ctrl[OFF_RESULT_LEN / 4];
  const outOff = OUTPUT_OFFSET - CTRL_BYTES;

  // Reset to IDLE for next call
  Atomics.store(ctrl, OFF_STATUS / 4, STATUS_IDLE);

  if (status === STATUS_ERROR) {
    const errMsg = new TextDecoder().decode(sabData.slice(outOff, outOff + resultLen));
    throw new Error(errMsg);
  }

  // Copy result out (must copy — SAB region will be overwritten on next call)
  return sabData.slice(outOff, outOff + resultLen);
}

// ── WASM memory helpers ─────────────────────────────────────────────

function getMemoryBuffer() {
  // Re-derive on each access — buffer detaches on memory.grow
  return new Uint8Array(wasmMemory.buffer);
}

function readWasmBytes(ptr, len) {
  if (len === 0) return new Uint8Array(0);
  return getMemoryBuffer().slice(ptr, ptr + len);
}

function writeWasmBytes(ptr, bytes) {
  getMemoryBuffer().set(bytes, ptr);
}

// ── Crypto host functions (WASM imports) ────────────────────────────

// random_bytes(out_ptr, n) -> uint32
function hostRandomBytes(outPtr, n) {
  try {
    const result = callHost(OP_RANDOM_BYTES, null, null, n);
    writeWasmBytes(outPtr, result);
    return result.byteLength;
  } catch (e) {
    lastError = e.message;
    return ERR_SENTINEL;
  }
}

// aes_gcm_encrypt(key_ptr, key_len, pt_ptr, pt_len, out_ptr) -> uint32
function hostAesGcmEncrypt(keyPtr, keyLen, ptPtr, ptLen, outPtr) {
  try {
    const key = readWasmBytes(keyPtr, keyLen);
    const pt = readWasmBytes(ptPtr, ptLen);
    const result = callHost(OP_AES_GCM_ENCRYPT, key, pt);
    writeWasmBytes(outPtr, result);
    return result.byteLength;
  } catch (e) {
    lastError = e.message;
    return ERR_SENTINEL;
  }
}

// aes_gcm_decrypt(key_ptr, key_len, ct_ptr, ct_len, out_ptr) -> uint32
function hostAesGcmDecrypt(keyPtr, keyLen, ctPtr, ctLen, outPtr) {
  try {
    const key = readWasmBytes(keyPtr, keyLen);
    const ct = readWasmBytes(ctPtr, ctLen);
    const result = callHost(OP_AES_GCM_DECRYPT, key, ct);
    writeWasmBytes(outPtr, result);
    return result.byteLength;
  } catch (e) {
    lastError = e.message;
    return ERR_SENTINEL;
  }
}

// hmac_sha256(key_ptr, key_len, data_ptr, data_len, out_ptr) -> uint32
function hostHmacSha256(keyPtr, keyLen, dataPtr, dataLen, outPtr) {
  try {
    const key = readWasmBytes(keyPtr, keyLen);
    const d = readWasmBytes(dataPtr, dataLen);
    const result = callHost(OP_HMAC_SHA256, key, d);
    writeWasmBytes(outPtr, result);
    return result.byteLength;
  } catch (e) {
    lastError = e.message;
    return ERR_SENTINEL;
  }
}

// rsa_oaep_sha1_encrypt(pub_ptr, pub_len, pt_ptr, pt_len, out_ptr) -> uint32
function hostRsaOaepEncrypt(pubPtr, pubLen, ptPtr, ptLen, outPtr) {
  try {
    const pub = readWasmBytes(pubPtr, pubLen);
    const pt = readWasmBytes(ptPtr, ptLen);
    const result = callHost(OP_RSA_OAEP_SHA1_ENCRYPT, pub, pt);
    writeWasmBytes(outPtr, result);
    return result.byteLength;
  } catch (e) {
    lastError = e.message;
    return ERR_SENTINEL;
  }
}

// rsa_oaep_sha1_decrypt(priv_ptr, priv_len, ct_ptr, ct_len, out_ptr) -> uint32
function hostRsaOaepDecrypt(privPtr, privLen, ctPtr, ctLen, outPtr) {
  try {
    const priv = readWasmBytes(privPtr, privLen);
    const ct = readWasmBytes(ctPtr, ctLen);
    const result = callHost(OP_RSA_OAEP_SHA1_DECRYPT, priv, ct);
    writeWasmBytes(outPtr, result);
    return result.byteLength;
  } catch (e) {
    lastError = e.message;
    return ERR_SENTINEL;
  }
}

// rsa_generate_keypair(bits, priv_out, pub_out, pub_len_ptr) -> uint32
function hostRsaGenerateKeypair(bits, privOut, pubOut, pubLenPtr) {
  try {
    const result = callHost(OP_RSA_GENERATE_KEYPAIR, null, null, bits);
    const privLen = ctrl[OFF_EXTRA / 4];
    const pubLen = result.byteLength - privLen;
    const privBytes = result.slice(0, privLen);
    const pubBytes = result.slice(privLen);
    writeWasmBytes(privOut, privBytes);
    writeWasmBytes(pubOut, pubBytes);
    // Write pub length as little-endian uint32
    const pubLenLE = new Uint8Array(4);
    new DataView(pubLenLE.buffer).setUint32(0, pubLen, true);
    writeWasmBytes(pubLenPtr, pubLenLE);
    return privLen;
  } catch (e) {
    lastError = e.message;
    return ERR_SENTINEL;
  }
}

// get_last_error(out_ptr, out_capacity) -> uint32
function hostGetLastError(outPtr, outCapacity) {
  if (!lastError) return 0;
  const encoded = new TextEncoder().encode(lastError);
  const len = Math.min(encoded.byteLength, outCapacity);
  writeWasmBytes(outPtr, encoded.slice(0, len));
  lastError = '';
  return len;
}

// ── I/O host functions (streaming encrypt via read_input/write_output) ──

let ioInput = null;      // Uint8Array — plaintext source
let ioInputOffset = 0;
let ioOutputChunks = []; // collected TDF output chunks

function hostReadInput(bufPtr, bufCapacity) {
  if (!ioInput || ioInputOffset >= ioInput.byteLength) return 0; // EOF
  const remaining = ioInput.byteLength - ioInputOffset;
  const n = Math.min(remaining, bufCapacity);
  writeWasmBytes(bufPtr, ioInput.subarray(ioInputOffset, ioInputOffset + n));
  ioInputOffset += n;
  return n;
}

function hostWriteOutput(bufPtr, bufLen) {
  const data = readWasmBytes(bufPtr, bufLen);
  ioOutputChunks.push(new Uint8Array(data));
  return bufLen;
}

// ── Minimal WASI stubs ──────────────────────────────────────────────
// Go's wasip1 runtime requires these. We provide minimal implementations.

class WasiExit extends Error {
  constructor(code) {
    super(`proc_exit(${code})`);
    this.code = code;
  }
}

function buildWasiImports() {
  return {
    proc_exit(code) {
      throw new WasiExit(code);
    },
    fd_write(fd, iovsPtr, iovsLen, nwrittenPtr) {
      // Minimal: just report 0 bytes written
      const mem = getMemoryBuffer();
      new DataView(mem.buffer).setUint32(nwrittenPtr, 0, true);
      return 0;
    },
    args_get() { return 0; },
    args_sizes_get(argcPtr, argvBufSizePtr) {
      const mem = getMemoryBuffer();
      const dv = new DataView(mem.buffer);
      dv.setUint32(argcPtr, 0, true);
      dv.setUint32(argvBufSizePtr, 0, true);
      return 0;
    },
    environ_get() { return 0; },
    environ_sizes_get(countPtr, bufSizePtr) {
      const mem = getMemoryBuffer();
      const dv = new DataView(mem.buffer);
      dv.setUint32(countPtr, 0, true);
      dv.setUint32(bufSizePtr, 0, true);
      return 0;
    },
    clock_time_get(clockId, precision, timePtr) {
      const now = BigInt(Math.floor(Date.now() * 1e6));
      const mem = getMemoryBuffer();
      new DataView(mem.buffer).setBigUint64(timePtr, now, true);
      return 0;
    },
    random_get(bufPtr, bufLen) {
      const buf = new Uint8Array(bufLen);
      crypto.getRandomValues(buf);
      writeWasmBytes(bufPtr, buf);
      return 0;
    },
    fd_close() { return 0; },
    fd_fdstat_get() { return 0; },
    fd_prestat_get() { return 8; }, // EBADF — no preopens
    fd_prestat_dir_name() { return 8; },
    fd_seek(fd, offsetLo, offsetHi, whence, newOffsetPtr) { return 0; },
    fd_read() { return 0; },
    path_open() { return 44; }, // ENOENT
    sched_yield() { return 0; },
  };
}

// ── WASM loading and initialization ─────────────────────────────────

async function initWasm(wasmUrl) {
  const wasiImports = buildWasiImports();

  const importObject = {
    wasi_snapshot_preview1: wasiImports,
    crypto: {
      random_bytes: hostRandomBytes,
      aes_gcm_encrypt: hostAesGcmEncrypt,
      aes_gcm_decrypt: hostAesGcmDecrypt,
      hmac_sha256: hostHmacSha256,
      rsa_oaep_sha1_encrypt: hostRsaOaepEncrypt,
      rsa_oaep_sha1_decrypt: hostRsaOaepDecrypt,
      rsa_generate_keypair: hostRsaGenerateKeypair,
      get_last_error: hostGetLastError,
    },
    io: {
      read_input: hostReadInput,
      write_output: hostWriteOutput,
    },
  };

  const resp = await fetch(wasmUrl);
  const { instance } = await WebAssembly.instantiateStreaming(resp, importObject);

  wasmInstance = instance;
  wasmMemory = instance.exports.memory;

  // Call _initialize (reactor mode — built with -buildmode=c-shared).
  // Unlike _start, this initializes the runtime without calling main()
  // or proc_exit, so the module stays alive for wasmexport calls.
  if (instance.exports._initialize) {
    instance.exports._initialize();
  } else if (instance.exports._start) {
    // Fallback for command-mode builds (standard Go).
    // proc_exit(0) will throw WasiExit — catch and continue.
    try {
      instance.exports._start();
    } catch (e) {
      if (!(e instanceof WasiExit)) throw e;
    }
  }
}

// ── Encrypt operation ───────────────────────────────────────────────

function wasmMalloc(size) {
  return wasmInstance.exports.tdf_malloc(size);
}

function writeStringToWasm(str) {
  const encoded = new TextEncoder().encode(str);
  if (encoded.byteLength === 0) return { ptr: 0, len: 0 };
  const ptr = wasmMalloc(encoded.byteLength);
  writeWasmBytes(ptr, encoded);
  return { ptr, len: encoded.byteLength };
}

function writeBytesToWasm(bytes) {
  if (!bytes || bytes.byteLength === 0) return { ptr: 0, len: 0 };
  const ptr = wasmMalloc(bytes.byteLength);
  writeWasmBytes(ptr, bytes);
  return { ptr, len: bytes.byteLength };
}

function getWasmError() {
  const bufSize = 1024;
  const bufPtr = wasmMalloc(bufSize);
  const n = wasmInstance.exports.get_error(bufPtr, bufSize);
  if (n === 0) return '';
  return new TextDecoder().decode(readWasmBytes(bufPtr, n));
}

function doEncrypt(kasPubPEM, kasURL, attrs, plaintext, integrityAlg, segIntegrityAlg, segmentSize) {
  const pub = writeStringToWasm(kasPubPEM);
  const url = writeStringToWasm(kasURL);
  const attrStr = attrs && attrs.length > 0 ? attrs.join('\n') : '';
  const attr = writeStringToWasm(attrStr);

  // Set up streaming I/O state
  ioInput = plaintext;
  ioInputOffset = 0;
  ioOutputChunks = [];

  const resultLen = wasmInstance.exports.tdf_encrypt(
    pub.ptr, pub.len,
    url.ptr, url.len,
    attr.ptr, attr.len,
    BigInt(plaintext.byteLength), // plaintextSize (i64)
    integrityAlg || 0,
    segIntegrityAlg || 0,
    segmentSize || 0,
  );

  if (resultLen === 0) {
    const errMsg = getWasmError();
    throw new Error(errMsg || 'tdf_encrypt returned 0');
  }

  // Concatenate output chunks
  const totalLen = ioOutputChunks.reduce((sum, c) => sum + c.byteLength, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of ioOutputChunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  ioInput = null;
  ioOutputChunks = [];
  return result;
}

// ── Message handler ─────────────────────────────────────────────────

self.onmessage = async (e) => {
  const msg = e.data;

  if (msg.type === 'init') {
    try {
      const sab = msg.sab;
      ctrl = new Int32Array(sab, 0, CTRL_BYTES / 4);
      data = new Uint8Array(sab, CTRL_BYTES);
      Atomics.store(ctrl, OFF_STATUS / 4, STATUS_IDLE);

      await initWasm(msg.wasmUrl);
      self.postMessage({ type: 'ready' });
    } catch (err) {
      self.postMessage({ type: 'error', id: null, message: err.message });
    }
    return;
  }

  if (msg.type === 'encrypt') {
    try {
      const result = doEncrypt(
        msg.kasPubPEM,
        msg.kasURL,
        msg.attrs,
        msg.plaintext,
        msg.integrityAlg,
        msg.segIntegrityAlg,
        msg.segmentSize,
      );
      // Transfer the ArrayBuffer for zero-copy
      self.postMessage({ type: 'result', id: msg.id, data: result }, [result.buffer]);
    } catch (err) {
      self.postMessage({ type: 'error', id: msg.id, message: err.message });
    }
    return;
  }
};
