import { expect, assert } from 'chai';
import { EncryptParamsBuilder } from '../../src/client/builders';

describe('EncyptParamsBuilder', () => {
  describe('setAttributes', () => {
    it('should accept valid attribute', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://example.com/attr/somarrt/value/someval' };
      paramsBuilder.withAttributes([attribute]);
    });

    it('should accept ip and port host', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://127.0.0.1:4000/attr/sameval/value/otherval' };
      paramsBuilder.withAttributes([attribute]);
    });

    it('should accept www host ', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://www.example.com/attr/sameval/value/otherval' };
      paramsBuilder.withAttributes([attribute]);
    });

    it('should not accept empty attributes', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const emptyAttribute = {};
      expect(() => paramsBuilder.withAttributes([emptyAttribute]).build()).to.throw(
        Error,
        /attribute prop should be a string/
      );
    });

    it('should check attrName uniq with attrVal', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://example.com/attr/sameval/value/sameval' };
      expect(() => paramsBuilder.withAttributes([attribute])).to.throw(
        Error,
        /attribute name should be unique/
      );
    });

    it('should not accept attribute wrapped with text', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attrUrl = 'http://example.com/attr/sameval/value/sameval';
      const attribute = { attribute: `sometext${attrUrl}somemoretext` };
      expect(() => paramsBuilder.withAttributes([attribute])).to.throw(
        Error,
        /attribute is in invalid format/
      );
    });

    it('should use remoteStorage param', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      paramsBuilder.withRcaSource();
      const res = paramsBuilder.build();
      assert.deepStrictEqual(res.rcaSource, true, 'param rcaSource should be present');
    });
  });
});
