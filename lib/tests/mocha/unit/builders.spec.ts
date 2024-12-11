import { expect } from 'chai';

import { type AttributeObject } from '../../../src/tdf/AttributeObject.js';
import { EncryptParamsBuilder } from '../../../tdf3/src/client/builders.js';

const aex = {
  kasUrl: 'https://kas',
  pubKey: 'PUBKEY',
};

describe('EncryptParamsBuilder', () => {
  describe('setAttributes', () => {
    it('should accept valid attribute', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://example.com/attr/somarrt/value/someval', ...aex };
      paramsBuilder.withAttributes([attribute]);
    });

    it('should accept ip and port host', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://127.0.0.1:4000/attr/sameval/value/otherval', ...aex };
      paramsBuilder.withAttributes([attribute]);
    });

    it('should accept www host ', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://www.example.com/attr/sameval/value/otherval', ...aex };
      paramsBuilder.withAttributes([attribute]);
    });

    it('should not accept empty attributes', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const emptyAttribute = { ...aex };
      expect(() =>
        paramsBuilder.withAttributes([emptyAttribute as unknown as AttributeObject]).build()
      ).to.throw(Error, /attribute prop should be a string/);
    });

    it('should check attrName uniq with attrVal', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attribute = { attribute: 'http://example.com/attr/sameval/value/sameval', ...aex };
      expect(() => paramsBuilder.withAttributes([attribute])).to.throw(
        Error,
        /attribute name should be unique/
      );
    });

    it('should not accept attribute wrapped with text', () => {
      const paramsBuilder = new EncryptParamsBuilder();
      const attrUrl = 'http://example.com/attr/sameval/value/sameval';
      const attribute = { attribute: `sometext${attrUrl}somemoretext`, ...aex };
      expect(() => paramsBuilder.withAttributes([attribute])).to.throw(
        Error,
        /attribute is in invalid format/
      );
    });
  });
});
