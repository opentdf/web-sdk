import { expect } from '@esm-bundle/chai';

import ResourceLocator from '../../../../src/nanotdf/models/ResourceLocator.js';
import { ResourceLocatorIdentifierEnum } from '../../../../src/nanotdf/enum/ResourceLocatorIdentifierEnum.js';

describe('NanoTDF.ResourceLocator', () => {
  for (const { u, kid, idt } of [
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
});
