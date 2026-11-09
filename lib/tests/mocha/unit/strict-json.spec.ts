import { expect } from 'chai';

import { canonicalJson, isCaseVariant, scanStrictJson } from '../../../tdf3/src/strict-json.js';

describe('strict-json', () => {
  describe('canonicalJson', () => {
    it('sorts members by UTF-16 code units and serializes numbers as ECMAScript does', () => {
      expect(canonicalJson({ b: [1, -0, 1e21, 0.1], a: '\u0007é', '😀': 1, '～': 2 })).to.equal(
        '{"a":"\\u0007é","b":[1,0,1e+21,0.1],"😀":1,"～":2}'
      );
    });

    it('accepts valid surrogate pairs', () => {
      expect(canonicalJson({ '😀': '😀' })).to.equal('{"😀":"😀"}');
    });

    for (const [what, s] of [
      ['a lone high surrogate', 'a\ud800b'],
      ['a lone low surrogate', 'a\udc00b'],
      ['a reversed pair', '\ude00\ud83d'],
      ['a trailing high surrogate', 'x\ud83d'],
    ]) {
      it(`rejects ${what} in a string or a member name`, () => {
        expect(() => canonicalJson(s)).to.throw(TypeError);
        expect(() => canonicalJson({ [s]: 1 })).to.throw(TypeError);
      });
    }

    it('rejects values that are not JSON', () => {
      for (const v of [Infinity, NaN, 1n, () => 1, new Date(0), new Uint8Array(1)]) {
        expect(() => canonicalJson(v)).to.throw(TypeError);
      }
    });
  });

  describe('isCaseVariant', () => {
    it('folds ASCII letters, long s, and the Kelvin sign only', () => {
      expect(isCaseVariant('ID', 'id')).to.be.true;
      expect(isCaseVariant('id', 'id')).to.be.false;
      expect(isCaseVariant('ſcope', 'scope')).to.be.true;
      expect(isCaseVariant('ıd', 'id')).to.be.false;
      expect(isCaseVariant('ids', 'id')).to.be.false;
    });
  });

  describe('scanStrictJson', () => {
    it('reports a lone surrogate inside an assertion but accepts a valid pair', () => {
      expect(scanStrictJson('{"id":"a","x":"\\ud83d\\ude00"}', 'assertion')).to.deep.equal({
        ok: true,
      });
      for (const s of ['\\ud800', '\\udc00', '\\ude00\\ud83d', '\\ud83dx']) {
        const scan = scanStrictJson(`{"id":"a","x":"${s}"}`, 'assertion');
        expect(scan.failure?.reason, s).to.equal('invalid-json');
        expect(scan.failure?.assertionId).to.equal('a');
      }
    });
  });
});
