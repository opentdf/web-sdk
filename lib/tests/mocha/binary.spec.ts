import { expect } from 'chai';
import { Binary } from '../../tdf3/src/binary.js';

describe('Binary', () => {
  describe('factory methods', () => {
    it('#fromArrayBuffer', () => {
      const arrayBuffer = Uint8Array.from([97, 98, 99]).buffer;
      const bin = Binary.fromArrayBuffer(arrayBuffer);
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.true;
      expect(bin.isByteArray()).to.be.false;
      expect(bin.isString()).to.be.false;
    });

    it('#fromBuffer', () => {
      const buffer = new Uint8Array([97, 98, 99]);
      const bin = Binary.fromArrayBuffer(buffer.buffer);
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.true;
    });

    it('#fromByteArray', () => {
      const byteArray = [97, 98, 99];
      const bin = Binary.fromByteArray(byteArray);
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.false;
      expect(bin.isByteArray()).to.be.true;
      expect(bin.isString()).to.be.false;
    });

    it('#fromString', () => {
      const bin = Binary.fromString('abc');
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.false;
      expect(bin.isByteArray()).to.be.false;
      expect(bin.isString()).to.be.true;
    });
  });
});
