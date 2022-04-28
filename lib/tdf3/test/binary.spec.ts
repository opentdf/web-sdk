import { expect } from 'chai';
import { Binary } from '../src/binary';

describe('Binary', () => {
  describe('factory methods', () => {
    it('#fromArrayBuffer', () => {
      const arrayBuffer = Uint8Array.from([97, 98, 99]).buffer;
      const bin = Binary.fromArrayBuffer(arrayBuffer);
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asBuffer()).to.eql(Buffer.from([97, 98, 99]));
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.true;
      expect(bin.isBuffer()).to.be.false;
      expect(bin.isByteArray()).to.be.false;
      expect(bin.isString()).to.be.false;
    });

    it('#fromBuffer', () => {
      const buffer = Buffer.from([97, 98, 99]);
      const bin = Binary.fromBuffer(buffer);
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asBuffer()).to.eql(Buffer.from([97, 98, 99]));
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.false;
      expect(bin.isBuffer()).to.be.true;
      expect(bin.isByteArray()).to.be.false;
      expect(bin.isString()).to.be.false;
    });

    it('#fromByteArray', () => {
      const byteArray = [97, 98, 99];
      const bin = Binary.fromByteArray(byteArray);
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asBuffer()).to.eql(Buffer.from([97, 98, 99]));
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.false;
      expect(bin.isBuffer()).to.be.false;
      expect(bin.isByteArray()).to.be.true;
      expect(bin.isString()).to.be.false;
    });

    it('#fromString', () => {
      const bin = Binary.fromString('abc');
      expect(bin.asArrayBuffer()).to.eql(Uint8Array.from([97, 98, 99]).buffer);
      expect(bin.asBuffer()).to.eql(Buffer.from([97, 98, 99]));
      expect(bin.asByteArray()).to.eql([97, 98, 99]);
      expect(bin.asString()).to.eql('abc');
      expect(bin.length()).to.eql(3);
      expect(bin.isArrayBuffer()).to.be.false;
      expect(bin.isBuffer()).to.be.false;
      expect(bin.isByteArray()).to.be.false;
      expect(bin.isString()).to.be.true;
    });
  });
});
