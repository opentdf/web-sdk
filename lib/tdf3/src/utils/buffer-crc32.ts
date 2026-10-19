// CRC-32 (ISO-HDLC, the ZIP and zlib CRC), computed incrementally.
//
// Encrypt runs every output byte through this, so it bounds encrypt
// throughput. Node and Bun have a native CRC-32 in zlib that is an order of
// magnitude faster than any JS loop; elsewhere a slice-by-16 table loop is
// about 4x faster than the byte-at-a-time loop it replaced.

type Crc32 = (data: Uint8Array, previous: number) => number;

const POLYNOMIAL = 0xedb88320;

// TABLES[k * 256 + b] is the CRC of byte b followed by k zero bytes, which lets
// the loop below fold 16 input bytes into the CRC per iteration.
const TABLES = (() => {
  const t = new Int32Array(16 * 256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? POLYNOMIAL ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c;
  }
  for (let k = 1; k < 16; k++) {
    for (let n = 0; n < 256; n++) {
      const prev = t[(k - 1) * 256 + n];
      t[k * 256 + n] = (prev >>> 8) ^ t[prev & 0xff];
    }
  }
  return t;
})();

/** Portable CRC-32: slice-by-16 over the input, byte at a time over the tail. */
export function portableCrc32(buf: Uint8Array, previous: number): number {
  const t = TABLES;
  let crc = ~previous;
  let i = 0;
  const end = buf.length - (buf.length & 15);
  for (; i < end; i += 16) {
    crc ^= buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24);
    crc =
      t[3840 + (crc & 0xff)] ^
      t[3584 + ((crc >>> 8) & 0xff)] ^
      t[3328 + ((crc >>> 16) & 0xff)] ^
      t[3072 + (crc >>> 24)] ^
      t[2816 + buf[i + 4]] ^
      t[2560 + buf[i + 5]] ^
      t[2304 + buf[i + 6]] ^
      t[2048 + buf[i + 7]] ^
      t[1792 + buf[i + 8]] ^
      t[1536 + buf[i + 9]] ^
      t[1280 + buf[i + 10]] ^
      t[1024 + buf[i + 11]] ^
      t[768 + buf[i + 12]] ^
      t[512 + buf[i + 13]] ^
      t[256 + buf[i + 14]] ^
      t[buf[i + 15]];
  }
  for (; i < buf.length; i++) {
    crc = t[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return ~crc >>> 0;
}

/**
 * zlib's `crc32(data, value)` (Node ≥ 20.15 / 22.2, Bun), or undefined.
 *
 * Reached through `process.getBuiltinModule` (Node ≥ 20.16 / 22.3) rather than
 * an import, so browser bundles never see a `node:zlib` dependency.
 */
const nativeCrc32: Crc32 | undefined = (() => {
  const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  try {
    const zlib = proc?.getBuiltinModule?.('node:zlib') as { crc32?: unknown } | undefined;
    return typeof zlib?.crc32 === 'function' ? (zlib.crc32 as Crc32) : undefined;
  } catch {
    return undefined;
  }
})();

/** Which implementation `unsigned` uses in this runtime. */
export const crc32Backend: 'zlib' | 'portable' = nativeCrc32 ? 'zlib' : 'portable';

/**
 * Continue a CRC-32 over `buf`. Start with `previous = 0`; returns the CRC as
 * an unsigned 32-bit integer.
 */
export const unsigned: Crc32 = nativeCrc32
  ? (buf, previous) => nativeCrc32(buf, previous >>> 0)
  : portableCrc32;
