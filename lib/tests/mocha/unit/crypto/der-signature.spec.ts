import { expect } from 'chai';

import { derToIeeeP1363, ieeeP1363ToDer } from '../../../../tdf3/src/crypto/core/signing.js';
import { ConfigurationError } from '../../../../src/errors.js';

/**
 * Direct unit tests for derToIeeeP1363's DER parsing. The happy path (real
 * signatures round-tripping through sign→verify) is covered in
 * crypto-service.spec.ts; these focus on malformed input, which must always
 * throw a controlled ConfigurationError rather than an out-of-bounds
 * RangeError/TypeError or a silently-truncated component.
 */
describe('derToIeeeP1363 DER validation', () => {
  it('RS256 passes through unchanged (no DER parsing)', () => {
    const sig = new Uint8Array([1, 2, 3]);
    expect(derToIeeeP1363(sig, 'RS256')).to.equal(sig);
  });

  describe('well-formed DER (positive controls)', () => {
    it('parses a minimal r=0x01, s=0x02 into a right-aligned 64-byte ES256 output', () => {
      // 0x30 seqLen 0x02 rLen r 0x02 sLen s
      const der = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
      const out = derToIeeeP1363(der, 'ES256');
      expect(out).to.have.length(64);
      expect(out[31]).to.equal(0x01); // r right-aligned in first 32 bytes
      expect(out[63]).to.equal(0x02); // s right-aligned in second 32 bytes
      // everything else zero-padded
      expect(out.slice(0, 31).every((b) => b === 0)).to.be.true;
      expect(out.slice(32, 63).every((b) => b === 0)).to.be.true;
    });

    it('strips a DER leading-zero pad byte (high-bit component)', () => {
      // r = 0x00 0x80 (zero-prefixed to stay positive) → 0x80 after stripping
      const der = new Uint8Array([0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]);
      const out = derToIeeeP1363(der, 'ES256');
      expect(out).to.have.length(64);
      expect(out[31]).to.equal(0x80);
      expect(out[63]).to.equal(0x01);
    });
  });

  describe('malformed DER throws ConfigurationError', () => {
    const cases: Array<{ name: string; bytes: number[]; match: RegExp }> = [
      { name: 'empty', bytes: [], match: /too short/ },
      { name: 'single 0x30 byte', bytes: [0x30], match: /too short/ },
      {
        name: 'wrong SEQUENCE tag',
        bytes: [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        match: /expected SEQUENCE/,
      },
      {
        name: 'missing INTEGER tag for r',
        bytes: [0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01],
        match: /expected INTEGER for r/,
      },
      {
        name: 'r INTEGER length overruns the buffer',
        bytes: [0x30, 0x06, 0x02, 0x40, 0x01, 0x02, 0x01, 0x01],
        match: /r INTEGER length out of range/,
      },
      {
        name: 's INTEGER length overruns the buffer',
        bytes: [0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x40, 0x01],
        match: /s INTEGER length out of range/,
      },
      {
        name: 'truncated before s INTEGER',
        bytes: [0x30, 0x82, 0x00, 0x08, 0x02, 0x01, 0x01, 0x02],
        match: /truncated before s INTEGER/,
      },
      {
        name: 'invalid long-form length (too many length bytes)',
        bytes: [0x30, 0x85, 0, 0, 0, 0, 0, 0],
        match: /invalid long-form length/,
      },
    ];

    for (const { name, bytes, match } of cases) {
      it(name, () => {
        expect(() => derToIeeeP1363(new Uint8Array(bytes), 'ES256')).to.throw(
          ConfigurationError,
          match
        );
      });
    }

    it('rejects an r component larger than the curve size (ES256)', () => {
      // r = 33 bytes, no leading zero → cannot fit a 32-byte P-256 slot.
      const rBytes = new Array(33).fill(0x7f);
      const der = new Uint8Array([
        0x30,
        2 + 33 + 3, // seqLen (short form): r INTEGER (2+33) + s INTEGER (2+1)
        0x02,
        33,
        ...rBytes,
        0x02,
        0x01,
        0x01,
      ]);
      expect(() => derToIeeeP1363(der, 'ES256')).to.throw(
        ConfigurationError,
        /component larger than expected/
      );
    });
  });
});

describe('ieeeP1363ToDer fixed-width validation', () => {
  for (const [algorithm, expectedLength] of [
    ['ES256', 64],
    ['ES384', 96],
    ['ES512', 132],
  ] as const) {
    it(`${algorithm} accepts exactly ${expectedLength} bytes`, () => {
      expect(ieeeP1363ToDer(new Uint8Array(expectedLength), algorithm)[0]).to.equal(0x30);
    });

    it(`${algorithm} rejects a shortened signature`, () => {
      expect(() => ieeeP1363ToDer(new Uint8Array(expectedLength - 1), algorithm)).to.throw(
        ConfigurationError,
        `expected ${expectedLength} bytes`
      );
    });
  }
});
