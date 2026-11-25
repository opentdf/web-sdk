import { expect } from 'chai';

import { isCaseVariant, scanStrictJson } from '../../../tdf3/src/strict-json.js';

describe('strict-json', () => {
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
