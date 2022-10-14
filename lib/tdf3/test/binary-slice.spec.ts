import { assert, expect } from 'chai';
import { Binary } from '../src/binary.js';

function range(a: number, b?: number): number[] {
  if (!b) {
    return [...Array(a).keys()];
  }
  const l = b - a;
  const r = new Array(l);
  for (let i = 0; i < l; i += 1) {
    r[i] = a + i;
  }
  return r;
}

function expectorate(b: number[]) {
  const arrayBufferBinary = Binary.fromArrayBuffer(Uint8Array.from(b).buffer);
  const bufferBinary = Binary.fromBuffer(Buffer.from(b));
  const byteArrayBinary = Binary.fromByteArray(b);
  const stringBinary = Binary.fromString(String.fromCharCode(...b));
  return { arrayBufferBinary, bufferBinary, byteArrayBinary, stringBinary };
}

function actuate(bin: Binary) {
  const arrayBufferBinary = Binary.fromArrayBuffer(bin.asArrayBuffer());
  const bufferBinary = Binary.fromBuffer(bin.asBuffer());
  const byteArrayBinary = Binary.fromByteArray(bin.asByteArray());
  const stringBinary = Binary.fromString(bin.asString());
  return { arrayBufferBinary, bufferBinary, byteArrayBinary, stringBinary };
}

describe('Slice method', function () {
  const els = expectorate(range(10));
  for (const [name, bin] of Object.entries(els)) {
    describe(`short slice ${name}`, () => {
      it('Start 0, end undefined', () => {
        const actual = bin.slice(0);
        expect(actual.length()).to.equal(10);
        expect(actuate(actual)).to.deep.equal(expectorate(range(10)));
      });
      it('Start 5, end undefined', () => {
        const actual = bin.slice(5);
        expect(actual.length()).to.equal(5);
        expect(actuate(actual)).to.deep.equal(expectorate(range(5, 10)));
      });
      it('Start -1, end undefined', () => {
        const actual = bin.slice(-1);
        expect(actual.length()).to.equal(1);
        expect(actuate(actual)).to.deep.equal(expectorate([9]));
      });
      it('Start 1, end 1', () => {
        const actual = bin.slice(1, 1);
        expect(actual.length()).to.equal(0);
        expect(actuate(actual)).to.deep.equal(expectorate([]));
      });
      it('Start 0, end 10', () => {
        const actual = bin.slice(0, 10);
        expect(actual.length()).to.equal(10);
        expect(actuate(actual)).to.deep.equal(expectorate(range(10)));
      });
      it('Start 5, end 10', () => {
        const actual = bin.slice(5, 10);
        expect(actual.length()).to.equal(5);
        expect(actuate(actual)).to.deep.equal(expectorate(range(5, 10)));
      });
      it('Start -5, end 7', () => {
        const actual = bin.slice(-5, 7);
        expect(actual.length()).to.equal(2);
        expect(actuate(actual)).to.deep.equal(expectorate([5, 6]));
      });

      it('Start -5, end -2', () => {
        const actual = bin.slice(-5, -2);
        expect(actual.length()).to.equal(3);
        expect(actuate(actual)).to.deep.equal(expectorate([5, 6, 7]));
      });
      it('Start 0, end 100', () => {
        const actual = bin.slice(0, 100);
        expect(actual.length()).to.equal(10);
        expect(actuate(actual)).to.deep.equal(expectorate(range(10)));
      });
    });
  }

  // TODO(PLAT-1106): Do these work with binary 2.0.x?
  // They fail since some asString methods utf-8 encode their contents.
  const longels = expectorate(range(256));
  for (const [name, bin] of Object.entries(longels)) {
    describe(`medium slice ${name}`, () => {
      it.skip('Start 0, end undefined', () => {
        // This demonstrates
        const actual = bin.slice(0);
        expect(actual.length()).to.equal(256);
        expect(actuate(actual)).to.deep.equal(expectorate(range(256)));
      });
      it.skip('Start 128, end undefined', () => {
        const actual = bin.slice(128);
        expect(actual.length()).to.equal(128);
        expect(actuate(actual)).to.deep.equal(expectorate(range(128, 256)));
      });
    });
  }

  describe('Slice between types', function () {
    it('Slice from String to ByteArray', function () {
      const buffer = '0123456789';
      const binary1 = Binary.fromString(buffer);
      const binary2 = Binary.fromByteArray(Binary.fromString(buffer).asByteArray());

      const result1 = binary1.slice(0);
      const result2 = binary2.slice(0);

      assert.equal(result1.asString(), result2.asString());
    });

    it('Slice from String to ArrayBuffer', function () {
      const buffer = '0123456789';
      const binary1 = Binary.fromString(buffer);
      const binary2 = Binary.fromArrayBuffer(Binary.fromString(buffer).asArrayBuffer());

      const result1 = binary1.slice(0);
      const result2 = binary2.slice(0);

      assert.equal(result1.asString(), result2.asString());
    });

    it('Slice from String to ByteArray test negatives (slice vs substring)', function () {
      const buffer = '0123456789';
      const binary1 = Binary.fromString(buffer);
      const binary2 = Binary.fromByteArray(Binary.fromString(buffer).asByteArray());

      const result1 = binary1.slice(-5, 7);
      const result2 = binary2.slice(-5, 7);

      assert.equal(result1.asString(), result2.asString());
    });

    it('Slice from String to ArrayBuffer test negatives (slice vs substring)', function () {
      const buffer = '0123456789';
      const binary1 = Binary.fromString(buffer);
      const binary2 = Binary.fromArrayBuffer(Binary.fromString(buffer).asArrayBuffer());

      const result1 = binary1.slice(-5, 7);
      const result2 = binary2.slice(-5, 7);

      assert.equal(result1.asString(), result2.asString());
    });
  });
});
