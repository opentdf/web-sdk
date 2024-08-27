import { expect } from '@esm-bundle/chai';

import * as hex from '../../../src/encodings/hex.js';

describe('hex', function () {
  describe('encode', function () {
    for (const { g, e } of [
      { g: 'Hello world', e: '48656c6c6f20776f726c64' },
      { g: '', e: '' },
      { g: ' ', e: '20' },
      { g: '\u0000', e: '00' },
    ]) {
      it(`("${g}") => ${e}`, () => {
        expect(hex.encode(g)).to.eql(e);
      });
    }
  });
  describe('encode throws', function () {
    for (const { g, e } of [
      { g: '🚩🚩🚩', e: 'invalid input' },
      { g: '\uffff', e: 'invalid input' },
    ]) {
      it(`("${g}") => ${e}`, () => {
        expect(() => hex.encode(g)).to.throw(e);
      });
    }
  });
  describe('encodeArrayBuffer', function () {
    for (const { g, e } of [
      { g: [], e: '' },
      { g: [0], e: '00' },
      { g: [255], e: 'ff' },
      { g: [255, 0, 32], e: 'ff0020' },
    ]) {
      it(`("${g}") => ${e}`, () => {
        expect(hex.encodeArrayBuffer(new Uint8Array(g).buffer)).to.eql(e);
      });
    }
  });

  describe('decode', function () {
    for (const { g, e } of [
      { g: '48656c6c6f20776f726c64', e: 'Hello world' },
      { g: '', e: '' },
      { g: '20', e: ' ' },
      { g: '466f6f', e: 'Foo' },
    ]) {
      it(`("${g}") => ${e}`, () => {
        expect(hex.decode(g)).to.eql(e);
      });
    }
  });
  describe('decode throws', function () {
    for (const { g, e } of [
      { g: '🚩🚩🚩', e: 'invalid input' },
      { g: 'ff ff', e: 'invalid input' },
    ]) {
      it(`("${g}") => ${e}`, () => {
        expect(() => hex.decode(g)).to.throw(e);
        expect(() => hex.decodeArrayBuffer(g)).to.throw(e);
      });
    }
  });
  describe('decodeArrayBuffer', function () {
    for (const { g, e } of [
      { g: '', e: [] },
      { g: '00', e: [0] },
      { g: 'ff', e: [255] },
      { g: 'ff0020', e: [255, 0, 32] },
    ]) {
      it(`("${g}") => ${e}`, () => {
        expect(hex.decodeArrayBuffer(g)).to.eql(new Uint8Array(e).buffer);
      });
    }
  });
});
