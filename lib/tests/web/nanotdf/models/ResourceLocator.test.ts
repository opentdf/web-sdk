import { expect } from '@esm-bundle/chai';

import ResourceLocator from '../../../../src/nanotdf/models/ResourceLocator.js';
import ResourceLocatorIdentifierEnum from '../../../../src/nanotdf/enum/ResourceLocatorIdentifierEnum.js';
import { hex } from '../../../../src/encodings/index.js';

describe('NanoTDF.ResourceLocator', () => {
  for (const { u, kid, idt } of [
    { u: 'http://a', idt: ResourceLocatorIdentifierEnum.None },
    { u: 'http://a', kid: 'r1', idt: ResourceLocatorIdentifierEnum.TwoBytes },
    { u: 'http://a', kid: '12345678', idt: ResourceLocatorIdentifierEnum.EightBytes },
    {
      u: 'http://a',
      kid: '12345678901234567890123456789012',
      idt: ResourceLocatorIdentifierEnum.ThirtyTwoBytes,
    },
  ]) {
    it(`ResourceLocator.parse("${u}", "${kid}")`, () => {
      const rl = ResourceLocator.parse(u, kid);
      expect(rl).to.have.property('identifierType', idt);
      expect(rl).to.have.property('identifier', kid);
    });
  }

  for (const { u, kid, v } of [
    { u: 'http://a', v: '00 01 61' },
    { u: 'https://a', v: '01 01 61' },
    { u: 'http://a', kid: 'r1', v: '10 01 61 72 31' },
    { u: 'https://a', kid: 'r1', v: '11 01 61 72 31' },
    { u: 'http://a', kid: '12345678', v: '20 01 61 31 32 33 34 35 36 37 38' },
    {
      u: 'http://a',
      kid: '12345678901234567890123456789012',
      v: '30 01 61 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32',
    },
  ]) {
    it(`new ResourceLocator("${u}", "${kid}")`, () => {
      const hexValue = v.replace(/\s/g, '');
      const ab = hex.decodeArrayBuffer(hexValue);
      const rl = new ResourceLocator(new Uint8Array(ab));
      expect(rl).to.have.property('identifier', kid);
      expect(rl).to.have.property('url', u);
    });
  }

  for (const { u, kid, msg } of [
    { u: 'http://a', kid: 'e0e0e0e0e0e0e0e0', msg: 'Unsupported identifier length: 16' },
    { u: 'gopher://a', kid: 'r1', msg: 'protocol unsupported' },
  ]) {
    it(`invalid resource locator`, () => {
      expect(() => ResourceLocator.parse(u, kid)).throw(msg);
    });
  }
});
