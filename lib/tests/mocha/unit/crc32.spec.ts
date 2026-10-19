import { expect } from 'chai';

import { crc32Backend, portableCrc32, unsigned } from '../../../tdf3/src/utils/buffer-crc32.js';

/** Bytes that are not all alike, so a skipped or repeated byte changes the CRC. */
function bytes(length: number, seed = 1): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed;
  for (let i = 0; i < length; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    out[i] = x >>> 24;
  }
  return out;
}

const ascii = (s: string) => new TextEncoder().encode(s);

/** Bit-at-a-time CRC-32: slow, but too simple to share a bug with the table code. */
function referenceCrc32(buf: Uint8Array, previous: number): number {
  let crc = ~previous;
  for (const byte of buf) {
    crc ^= byte;
    for (let k = 0; k < 8; k++) {
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
  }
  return ~crc >>> 0;
}

/** These specs also run bundled in a browser (karma), where there is no zlib. */
const isNode = typeof process !== 'undefined' && !!process.versions?.node;

describe('CRC-32', function () {
  for (const [name, crc32] of [
    ['unsigned', unsigned],
    ['portableCrc32', portableCrc32],
  ] as const) {
    describe(name, function () {
      it('matches the standard check values', function () {
        expect(crc32(new Uint8Array(0), 0)).to.equal(0);
        expect(crc32(ascii('123456789'), 0)).to.equal(0xcbf43926);
        expect(crc32(ascii('The quick brown fox jumps over the lazy dog'), 0)).to.equal(0x414fa339);
      });

      it('returns an unsigned value', function () {
        expect(crc32(new Uint8Array([0xff]), 0)).to.equal(0xff000000);
      });

      it('continues across any split point', function () {
        const data = bytes(100);
        const whole = crc32(data, 0);
        for (let at = 0; at <= data.length; at++) {
          expect(crc32(data.subarray(at), crc32(data.subarray(0, at), 0))).to.equal(whole);
        }
      });
    });
  }

  it('portableCrc32 agrees with the reference on every length and alignment around a block', function () {
    const data = bytes(80, 7);
    for (let start = 0; start < 17; start++) {
      for (let end = start; end <= data.length; end++) {
        const view = data.subarray(start, end);
        expect(portableCrc32(view, 0x12345678)).to.equal(referenceCrc32(view, 0x12345678));
      }
    }
  });

  it('unsigned agrees with portableCrc32 on a large buffer', function () {
    const data = bytes(1 << 20, 3);
    expect(unsigned(data, 0)).to.equal(portableCrc32(data, 0));
  });

  it('unsigned uses the native CRC-32 under Node', function () {
    // Under Node `unsigned` must be zlib, or encrypt silently loses most of its throughput.
    expect(crc32Backend).to.equal(isNode ? 'zlib' : 'portable');
  });
});
