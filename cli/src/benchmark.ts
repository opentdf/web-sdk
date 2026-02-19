import { performance } from 'node:perf_hooks';
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  publicEncrypt,
  privateDecrypt,
  generateKeyPairSync,
  constants,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { AuthProviders, OpenTDF, type DecoratedStream } from '@opentdf/sdk';

// ── Utility functions ───────────────────────────────────────────────

function parseSizes(s: string): number[] {
  return s
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map((p) => {
      const n = parseInt(p, 10);
      if (isNaN(n) || n <= 0) throw new Error(`invalid size: ${p}`);
      return n;
    });
}

function formatSize(n: number): string {
  const mb = 1024 * 1024;
  const kb = 1024;
  if (n >= mb && n % mb === 0) return `${n / mb} MB`;
  if (n >= kb && n % kb === 0) return `${n / kb} KB`;
  return `${n} B`;
}

function fmtDurationMS(ms: number): string {
  return `${ms.toFixed(1)} ms`;
}

function generatePayload(size: number): Uint8Array {
  const buf = new Uint8Array(size);
  const chunkSize = 65536;
  for (let offset = 0; offset < size; offset += chunkSize) {
    const len = Math.min(chunkSize, size - offset);
    const chunk = randomBytes(len);
    buf.set(chunk, offset);
  }
  return buf;
}

async function streamToBuffer(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let totalLength = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    totalLength += value.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

// ── WASM host implementation (synchronous Node.js crypto) ───────────

const ERR_SENTINEL = 0xffffffff;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let wasmInstance: any = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let wasmMemory: any = null;
let wasmLastError = '';
let wasmOK = false;

function getMemBuf(): Uint8Array {
  return new Uint8Array(wasmMemory!.buffer);
}

function readWasm(ptr: number, len: number): Uint8Array {
  if (len === 0) return new Uint8Array(0);
  return getMemBuf().slice(ptr, ptr + len);
}

function writeWasm(ptr: number, data: Uint8Array): void {
  getMemBuf().set(data, ptr);
}

// Crypto host functions (synchronous, using node:crypto)

function hostRandomBytes(outPtr: number, n: number): number {
  try {
    const bytes = randomBytes(n);
    writeWasm(outPtr, bytes);
    return n;
  } catch (e: any) {
    wasmLastError = e.message;
    return ERR_SENTINEL;
  }
}

function hostAesGcmEncrypt(
  keyPtr: number,
  keyLen: number,
  ptPtr: number,
  ptLen: number,
  outPtr: number
): number {
  try {
    const key = readWasm(keyPtr, keyLen);
    const pt = readWasm(ptPtr, ptLen);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ct = cipher.update(pt);
    cipher.final();
    const tag = cipher.getAuthTag();
    // Result: [iv(12) || ciphertext || tag(16)]
    const result = new Uint8Array(12 + ct.length + 16);
    result.set(iv, 0);
    result.set(ct, 12);
    result.set(tag, 12 + ct.length);
    writeWasm(outPtr, result);
    return result.length;
  } catch (e: any) {
    wasmLastError = e.message;
    return ERR_SENTINEL;
  }
}

function hostAesGcmDecrypt(
  keyPtr: number,
  keyLen: number,
  ctPtr: number,
  ctLen: number,
  outPtr: number
): number {
  try {
    const key = readWasm(keyPtr, keyLen);
    const data = readWasm(ctPtr, ctLen);
    if (data.length < 28) throw new Error('ciphertext too short for AES-GCM');
    const iv = data.slice(0, 12);
    const body = data.slice(12, data.length - 16);
    const tag = data.slice(data.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const pt = decipher.update(body);
    decipher.final();
    writeWasm(outPtr, pt);
    return pt.length;
  } catch (e: any) {
    wasmLastError = e.message;
    return ERR_SENTINEL;
  }
}

function hostHmacSha256(
  keyPtr: number,
  keyLen: number,
  dataPtr: number,
  dataLen: number,
  outPtr: number
): number {
  try {
    const key = readWasm(keyPtr, keyLen);
    const data = readWasm(dataPtr, dataLen);
    const hmac = createHmac('sha256', key).update(data).digest();
    writeWasm(outPtr, hmac);
    return hmac.length;
  } catch (e: any) {
    wasmLastError = e.message;
    return ERR_SENTINEL;
  }
}

function hostRsaOaepEncrypt(
  pubPtr: number,
  pubLen: number,
  ptPtr: number,
  ptLen: number,
  outPtr: number
): number {
  try {
    const pubPem = Buffer.from(readWasm(pubPtr, pubLen)).toString('utf8');
    const pt = readWasm(ptPtr, ptLen);
    const ct = publicEncrypt(
      { key: pubPem, oaepHash: 'sha1', padding: constants.RSA_PKCS1_OAEP_PADDING },
      pt
    );
    writeWasm(outPtr, ct);
    return ct.length;
  } catch (e: any) {
    wasmLastError = e.message;
    return ERR_SENTINEL;
  }
}

function hostRsaOaepDecrypt(
  privPtr: number,
  privLen: number,
  ctPtr: number,
  ctLen: number,
  outPtr: number
): number {
  try {
    const privPem = Buffer.from(readWasm(privPtr, privLen)).toString('utf8');
    const ct = readWasm(ctPtr, ctLen);
    const pt = privateDecrypt(
      { key: privPem, oaepHash: 'sha1', padding: constants.RSA_PKCS1_OAEP_PADDING },
      ct
    );
    writeWasm(outPtr, pt);
    return pt.length;
  } catch (e: any) {
    wasmLastError = e.message;
    return ERR_SENTINEL;
  }
}

function hostRsaGenerateKeypair(
  _bits: number,
  privOut: number,
  pubOut: number,
  pubLenPtr: number
): number {
  try {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const privBytes = Buffer.from(privateKey as string, 'utf8');
    const pubBytes = Buffer.from(publicKey as string, 'utf8');
    writeWasm(privOut, privBytes);
    writeWasm(pubOut, pubBytes);
    // Write pub length as little-endian uint32
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, pubBytes.length, true);
    writeWasm(pubLenPtr, lenBuf);
    return privBytes.length;
  } catch (e: any) {
    wasmLastError = e.message;
    return ERR_SENTINEL;
  }
}

function hostGetLastError(outPtr: number, outCapacity: number): number {
  if (!wasmLastError) return 0;
  const encoded = Buffer.from(wasmLastError, 'utf8');
  const len = Math.min(encoded.length, outCapacity);
  writeWasm(outPtr, encoded.slice(0, len));
  wasmLastError = '';
  return len;
}

// WASI stubs for Go wasip1 runtime

class WasiExit extends Error {
  code: number;
  constructor(code: number) {
    super(`proc_exit(${code})`);
    this.code = code;
  }
}

function buildWasiImports(): Record<string, Function> {
  return {
    proc_exit(code: number) {
      throw new WasiExit(code);
    },
    fd_write(_fd: number, _iovsPtr: number, _iovsLen: number, nwrittenPtr: number) {
      const dv = new DataView(wasmMemory!.buffer);
      dv.setUint32(nwrittenPtr, 0, true);
      return 0;
    },
    args_get() {
      return 0;
    },
    args_sizes_get(argcPtr: number, argvBufSizePtr: number) {
      const dv = new DataView(wasmMemory!.buffer);
      dv.setUint32(argcPtr, 0, true);
      dv.setUint32(argvBufSizePtr, 0, true);
      return 0;
    },
    environ_get() {
      return 0;
    },
    environ_sizes_get(countPtr: number, bufSizePtr: number) {
      const dv = new DataView(wasmMemory!.buffer);
      dv.setUint32(countPtr, 0, true);
      dv.setUint32(bufSizePtr, 0, true);
      return 0;
    },
    clock_time_get(_clockId: number, _precision: bigint, timePtr: number) {
      const now = BigInt(Math.floor(Date.now() * 1e6));
      const dv = new DataView(wasmMemory!.buffer);
      dv.setBigUint64(timePtr, now, true);
      return 0;
    },
    random_get(bufPtr: number, bufLen: number) {
      const bytes = randomBytes(bufLen);
      writeWasm(bufPtr, bytes);
      return 0;
    },
    fd_close() {
      return 0;
    },
    fd_fdstat_get() {
      return 0;
    },
    fd_prestat_get() {
      return 8;
    }, // EBADF
    fd_prestat_dir_name() {
      return 8;
    },
    fd_seek() {
      return 0;
    },
    fd_read() {
      return 0;
    },
    path_open() {
      return 44;
    }, // ENOENT
    sched_yield() {
      return 0;
    },
    fd_fdstat_set_flags() {
      return 0;
    },
    poll_oneoff(_inPtr: number, _outPtr: number, _nsubscriptions: number, neventsPtr: number) {
      const dv = new DataView(wasmMemory!.buffer);
      dv.setUint32(neventsPtr, 0, true);
      return 0;
    },
  };
}

function initWasm(wasmPath: string): void {
  wasmLastError = '';
  const wasmBytes = readFileSync(wasmPath);

  const importObject = {
    wasi_snapshot_preview1: buildWasiImports(),
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
      read_input: () => 0,
      write_output: () => ERR_SENTINEL,
    },
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const WA = (globalThis as any).WebAssembly;
  const mod = new WA.Module(new Uint8Array(wasmBytes));
  const instance = new WA.Instance(mod, importObject);
  wasmInstance = instance;
  wasmMemory = instance.exports.memory;

  // Initialize — reactor mode (c-shared) uses _initialize; command mode uses _start
  if (instance.exports._initialize) {
    (instance.exports._initialize as Function)();
  } else if (instance.exports._start) {
    try {
      (instance.exports._start as Function)();
    } catch (e) {
      if (!(e instanceof WasiExit)) throw e;
    }
  }
}

// ── WASM memory helpers ─────────────────────────────────────────────

function wasmMalloc(size: number): number {
  return (wasmInstance!.exports.tdf_malloc as Function)(size) as number;
}

function allocAndWrite(data: Uint8Array): number {
  const ptr = wasmMalloc(data.length);
  writeWasm(ptr, data);
  return ptr;
}

function getWasmError(): string {
  const bufSize = 4096;
  const bufPtr = wasmMalloc(bufSize);
  const n = (wasmInstance!.exports.get_error as Function)(bufPtr, bufSize) as number;
  if (n === 0) return '';
  return Buffer.from(readWasm(bufPtr, n)).toString('utf8');
}

// ── WASM encrypt ────────────────────────────────────────────────────

function wasmEncrypt(kasPubPEM: string, plaintext: Uint8Array): Uint8Array {
  const kasPubBytes = Buffer.from(kasPubPEM, 'utf8');
  const kasURLBytes = Buffer.from('https://kas.example.com', 'utf8');
  const attrBytes = Buffer.from('https://example.com/attr/classification/value/secret', 'utf8');

  const kasPubPtr = allocAndWrite(kasPubBytes);
  const kasURLPtr = allocAndWrite(kasURLBytes);
  const attrPtr = allocAndWrite(attrBytes);
  const ptPtr = allocAndWrite(plaintext);

  const outCapacity = plaintext.length * 2 + 65536;
  const outPtr = wasmMalloc(outCapacity);

  const resultLen = (wasmInstance!.exports.tdf_encrypt as Function)(
    kasPubPtr,
    kasPubBytes.length,
    kasURLPtr,
    kasURLBytes.length,
    attrPtr,
    attrBytes.length,
    ptPtr,
    plaintext.length,
    outPtr,
    outCapacity,
    0,
    0, // HS256 for root + segment integrity
    0 // default segment size
  ) as number;

  if (resultLen === 0) {
    const err = getWasmError();
    throw new Error('WASM encrypt failed: ' + (err || 'unknown error'));
  }

  return readWasm(outPtr, resultLen);
}

// ─��� Inline ZIP parser ───────────────────────────────────────────────

function parseZip(buf: Uint8Array): Record<string, Uint8Array> {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const files: Record<string, Uint8Array> = {};

  // Find EOCD signature scanning backwards
  let eocdOffset = -1;
  for (let i = buf.byteLength - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) throw new Error('ZIP: EOCD not found');

  const cdOffset = view.getUint32(eocdOffset + 16, true);
  const cdCount = view.getUint16(eocdOffset + 10, true);

  // Parse central directory entries
  const entries: { name: string; compSize: number; localOffset: number }[] = [];
  let pos = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (view.getUint32(pos, true) !== 0x02014b50) break;
    const compSize = view.getUint32(pos + 20, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const localOffset = view.getUint32(pos + 42, true);
    const name = Buffer.from(buf.slice(pos + 46, pos + 46 + nameLen)).toString('utf8');
    entries.push({ name, compSize, localOffset });
    pos += 46 + nameLen + extraLen + commentLen;
  }

  // Extract file data from local headers using central directory sizes
  for (const entry of entries) {
    const lhOff = entry.localOffset;
    const lhNameLen = view.getUint16(lhOff + 26, true);
    const lhExtraLen = view.getUint16(lhOff + 28, true);
    const dataStart = lhOff + 30 + lhNameLen + lhExtraLen;
    files[entry.name] = buf.slice(dataStart, dataStart + entry.compSize);
  }
  return files;
}

// ── DEK unwrap ──────────────────────────────────────────────────────

function unwrapDEKLocal(tdfBytes: Uint8Array, privPEM: string): Buffer {
  const files = parseZip(tdfBytes);
  const manifestBytes = files['0.manifest.json'];
  if (!manifestBytes) throw new Error('0.manifest.json not found in TDF ZIP');

  const manifest = JSON.parse(Buffer.from(manifestBytes).toString('utf8'));
  const wrappedKeyB64 = manifest.encryptionInformation.keyAccess[0].wrappedKey;
  const wrappedKey = Buffer.from(wrappedKeyB64, 'base64');
  const dek = privateDecrypt(
    { key: privPEM, oaepHash: 'sha1', padding: constants.RSA_PKCS1_OAEP_PADDING },
    wrappedKey
  );
  if (dek.length !== 32) {
    throw new Error(`DEK length: got ${dek.length}, want 32`);
  }
  return dek;
}

// ── WASM decrypt ────────────────────────────────────────────────────

function wasmDecrypt(tdfBytes: Uint8Array, dek: Buffer): Uint8Array {
  const tdfPtr = allocAndWrite(tdfBytes);
  const dekPtr = allocAndWrite(dek);

  const outCapacity = tdfBytes.length;
  const outPtr = wasmMalloc(outCapacity);

  const resultLen = (wasmInstance!.exports.tdf_decrypt as Function)(
    tdfPtr,
    tdfBytes.length,
    dekPtr,
    dek.length,
    outPtr,
    outCapacity
  ) as number;

  if (resultLen === 0) {
    const err = getWasmError();
    if (err) throw new Error('WASM decrypt failed: ' + err);
    return new Uint8Array(0);
  }

  return readWasm(outPtr, resultLen);
}

// ── Main benchmark ──────────────────────────────────────────────────

async function main() {
  const __dirname = dirname(fileURLToPath(import.meta.url));

  const argv = await yargs(hideBin(process.argv))
    .option('iterations', {
      alias: 'i',
      type: 'number',
      default: 5,
      description: 'Iterations per payload size to average',
    })
    .option('sizes', {
      alias: 's',
      type: 'string',
      default: '256,1024,16384,65536,262144,1048576',
      description: 'Comma-separated payload sizes in bytes',
    })
    .option('platformUrl', {
      type: 'string',
      default: 'http://localhost:8080',
      description: 'Platform URL',
    })
    .option('kasEndpoint', {
      type: 'string',
      default: 'http://localhost:8080/kas',
      description: 'KAS endpoint',
    })
    .option('oidcEndpoint', {
      type: 'string',
      default: 'http://localhost:8888/auth/realms/opentdf',
      description: 'OIDC endpoint',
    })
    .option('clientId', {
      type: 'string',
      default: 'opentdf',
      description: 'OAuth client ID',
    })
    .option('clientSecret', {
      type: 'string',
      default: 'secret',
      description: 'OAuth client secret',
    })
    .option('attribute', {
      alias: 'a',
      type: 'string',
      default: 'https://example.com/attr/attr1/value/value1',
      description: 'Data attribute',
    })
    .option('wasmBinary', {
      alias: 'w',
      type: 'string',
      default: resolve(__dirname, '../../../wasm-host/tdfcore.wasm'),
      description: 'Path to tdfcore.wasm',
    })
    .help()
    .parseAsync();

  const iterations = argv.iterations;
  const sizes = parseSizes(argv.sizes);
  const { platformUrl, kasEndpoint, oidcEndpoint, clientId, clientSecret, attribute } = argv;
  const wasmBinaryPath = argv.wasmBinary;

  // Setup auth
  const authProvider = await AuthProviders.clientSecretAuthProvider({
    clientId,
    oidcOrigin: oidcEndpoint,
    exchange: 'client',
    clientSecret,
  });

  const client = new OpenTDF({
    authProvider,
    platformUrl,
    defaultCreateOptions: {
      defaultKASEndpoint: kasEndpoint,
    },
  });

  // Setup WASM runtime + RSA keypair
  console.log('Initializing WASM runtime (Node.js WebAssembly)...');
  let wasmPubPEM = '';
  let wasmPrivPEM = '';
  try {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    wasmPubPEM = publicKey as string;
    wasmPrivPEM = privateKey as string;
    initWasm(wasmBinaryPath);
    wasmOK = true;
    console.log('WASM runtime initialized.');
  } catch (e: any) {
    console.log('WASM init failed: ' + e.message);
    wasmOK = false;
  }

  const encryptTimes: number[] = [];
  const decryptTimes: number[] = [];
  const wasmEncryptTimes: (number | null)[] = [];
  const wasmDecryptTimes: (number | null)[] = [];
  const wasmEncErrors: (string | null)[] = [];
  const wasmDecErrors: (string | null)[] = [];

  for (let si = 0; si < sizes.length; si++) {
    const size = sizes[si];
    const payload = generatePayload(size);
    console.log(`Benchmarking ${formatSize(size)} ...`);

    // ── Native SDK encrypt ──────────────────────────────────
    let lastTdf: Uint8Array | null = null;
    let encTotal = 0;
    for (let j = 0; j < iterations; j++) {
      const start = performance.now();
      const ct: DecoratedStream = await client.createZTDF({
        source: { type: 'buffer', location: payload },
        attributes: [attribute],
        autoconfigure: false,
      });
      const tdfBytes = await streamToBuffer(ct);
      encTotal += performance.now() - start;
      lastTdf = tdfBytes;
    }
    encryptTimes.push(encTotal / iterations);

    // ── WASM encrypt ────────────────────────────────────────
    let wasmTdf: Uint8Array | null = null;
    if (wasmOK) {
      try {
        let wasmEncTotal = 0;
        for (let j = 0; j < iterations; j++) {
          const start = performance.now();
          const tdf = wasmEncrypt(wasmPubPEM, payload);
          wasmEncTotal += performance.now() - start;
          wasmTdf = tdf;
        }
        wasmEncryptTimes.push(wasmEncTotal / iterations);
        wasmEncErrors.push(null);
      } catch (e: any) {
        console.log(`  WASM encrypt failed: ${e.message}`);
        wasmEncryptTimes.push(null);
        wasmEncErrors.push('OOM');
        // Reinit WASM runtime
        try {
          initWasm(wasmBinaryPath);
          wasmOK = true;
        } catch (reinitErr: any) {
          console.log(`  WASM runtime reinit failed: ${reinitErr.message}`);
          wasmOK = false;
        }
      }
    } else {
      wasmEncryptTimes.push(null);
      wasmEncErrors.push('N/A');
    }

    // ── Native SDK decrypt ──────────────────────────────────
    let decTotal = 0;
    for (let j = 0; j < iterations; j++) {
      const start = performance.now();
      const pt: DecoratedStream = await client.read({
        source: { type: 'buffer', location: lastTdf! },
      });
      await streamToBuffer(pt);
      decTotal += performance.now() - start;
    }
    decryptTimes.push(decTotal / iterations);

    // ── WASM decrypt ────────────────────────────────────────
    if (wasmTdf && wasmOK) {
      try {
        let wasmDecTotal = 0;
        for (let j = 0; j < iterations; j++) {
          const start = performance.now();
          const dek = unwrapDEKLocal(wasmTdf, wasmPrivPEM);
          wasmDecrypt(wasmTdf, dek);
          wasmDecTotal += performance.now() - start;
        }
        wasmDecryptTimes.push(wasmDecTotal / iterations);
        wasmDecErrors.push(null);
      } catch (e: any) {
        console.log(`  WASM decrypt failed: ${e.message}`);
        wasmDecryptTimes.push(null);
        wasmDecErrors.push('OOM');
        try {
          initWasm(wasmBinaryPath);
          wasmOK = true;
        } catch (reinitErr: any) {
          console.log(`  WASM runtime reinit failed: ${reinitErr.message}`);
          wasmOK = false;
        }
      }
    } else if (wasmEncErrors[si]) {
      wasmDecryptTimes.push(null);
      wasmDecErrors.push('N/A');
    } else if (!wasmOK) {
      wasmDecryptTimes.push(null);
      wasmDecErrors.push('N/A');
    } else {
      wasmDecryptTimes.push(null);
      wasmDecErrors.push(null);
    }
  }

  // Print results
  console.log();
  console.log('# Cross-SDK Benchmark Results');
  console.log(`Platform: ${platformUrl}`);
  console.log(`Iterations: ${iterations} per size`);
  console.log();

  console.log('## Encrypt');
  console.log('| Payload | TypeScript SDK | WASM |');
  console.log('|---------|----------------|------|');
  for (let i = 0; i < sizes.length; i++) {
    const wasmCol = wasmEncErrors[i] ? wasmEncErrors[i] : fmtDurationMS(wasmEncryptTimes[i]!);
    console.log(`| ${formatSize(sizes[i])} | ${fmtDurationMS(encryptTimes[i])} | ${wasmCol} |`);
  }

  console.log();
  console.log('## Decrypt');
  console.log('| Payload | TypeScript SDK* | WASM** |');
  console.log('|---------|-----------------|--------|');
  for (let i = 0; i < sizes.length; i++) {
    const wasmCol = wasmDecErrors[i] ? wasmDecErrors[i] : fmtDurationMS(wasmDecryptTimes[i]!);
    console.log(`| ${formatSize(sizes[i])} | ${fmtDurationMS(decryptTimes[i])} | ${wasmCol} |`);
  }
  console.log('*TypeScript SDK: includes KAS rewrap network latency');
  console.log(
    '**WASM: includes local RSA-OAEP DEK unwrap (no network); in production the host would call KAS for rewrap'
  );

  client.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
