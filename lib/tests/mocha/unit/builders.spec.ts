import { expect } from 'chai';

import { type AttributeObject } from '../../../tdf3/src/models/attribute.js';
import { DecryptParamsBuilder, EncryptParamsBuilder } from '../../../tdf3/src/client/builders.js';
import { ConfigurationError } from '../../../src/errors.js';

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

describe('DecryptParamsBuilder', () => {
  it('should store segment scheduler tuning', () => {
    const params = new DecryptParamsBuilder()
      .withStringSource('ciphertext')
      .withSegmentBatchSize(4)
      .withMaxConcurrentSegmentBatches(2)
      .build();

    expect(params.segmentBatchSize).to.equal(4);
    expect(params.maxConcurrentSegmentBatches).to.equal(2);
  });

  it('should store a plaintext range', () => {
    const build = (builder: DecryptParamsBuilder) => builder.withStringSource('ciphertext').build();
    expect(build(new DecryptParamsBuilder().withRange(2 ** 33, 10)).range).to.deep.equal({
      offset: 2 ** 33,
      length: 10,
    });
    expect(build(new DecryptParamsBuilder().withRange(5)).range).to.deep.equal({ offset: 5 });
  });

  it('should reject an invalid plaintext range', () => {
    expect(() => new DecryptParamsBuilder().withRange(-1)).to.throw(ConfigurationError, 'offset');
    expect(() => new DecryptParamsBuilder().withRange(0, 1.5)).to.throw(
      ConfigurationError,
      'length'
    );
  });
});
