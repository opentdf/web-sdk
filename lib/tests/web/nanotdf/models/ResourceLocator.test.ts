import { expect } from '@esm-bundle/chai';

import ResourceLocator from '../../../../src/nanotdf/models/ResourceLocator.js';
import ResourceLocatorIdentifierEnum from '../../../../src/nanotdf/enum/ResourceLocatorIdentifierEnum.js';
import { hex } from '../../../../src/encodings/index.js';

describe('NanoTDF.ResourceLocator', () => {
  for (const { u, kid, idt, v } of [
    { u: 'http://a', idt: ResourceLocatorIdentifierEnum.None, v: '00 01 61' },
    { u: 'https://a', idt: ResourceLocatorIdentifierEnum.None, v: '01 01 61' },
    { u: 'http://a', kid: 'a', idt: ResourceLocatorIdentifierEnum.TwoBytes, v: '10 01 61 61 00' },
    { u: 'http://a', kid: 'r1', idt: ResourceLocatorIdentifierEnum.TwoBytes, v: '10 01 61 72 31' },
    { u: 'https://a', kid: 'a', idt: ResourceLocatorIdentifierEnum.TwoBytes, v: '11 01 61 61 00' },
    { u: 'https://a', kid: 'r1', idt: ResourceLocatorIdentifierEnum.TwoBytes, v: '11 01 61 72 31' },
    {
      u: 'http://a',
      kid: '12345678',
      idt: ResourceLocatorIdentifierEnum.EightBytes,
      v: '20 01 61 31 32 33 34 35 36 37 38',
    },
    {
      u: 'http://a',
      kid: '12345',
      idt: ResourceLocatorIdentifierEnum.EightBytes,
      v: '20 01 61 31 32 33 34 35 00 00 00',
    },
    {
      u: 'http://a',
      kid: '12345678',
      idt: ResourceLocatorIdentifierEnum.EightBytes,
      v: '20 01 61 31 32 33 34 35 36 37 38',
    },
    {
      u: 'http://a',
      kid: '1234567890123456',
      idt: ResourceLocatorIdentifierEnum.ThirtyTwoBytes,
      v: '30 01 61 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    },
    {
      u: 'http://a',
      kid: '12345678901234567890123456789012',
      idt: ResourceLocatorIdentifierEnum.ThirtyTwoBytes,
      v: '30 01 61 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32',
    },
  ]) {
    const hexValue = v.replace(/\s/g, '');
    const ab = hex.decodeArrayBuffer(hexValue);
    it(`ResourceLocator.parse() => (${u}, "${kid}")`, () => {
      const rl = ResourceLocator.parse(new Uint8Array(ab));
      expect(rl).to.have.property('id', kid);
      expect(rl).to.have.property('identifier', kid ?? '');
      expect(rl).to.have.property('url', u);
    });
    it(`ResourceLocator.fromURL("${u}", "${kid}")`, () => {
      const rl = ResourceLocator.fromURL(u, kid);
      expect(rl).to.have.property('idType', idt);
      expect(rl).to.have.property('id', kid);
      expect(rl).to.have.property('identifier', kid ?? '');
      expect(hex.encodeArrayBuffer(rl.toBuffer())).to.eql(hexValue);
    });
  }

  for (const { v, msg } of [
    { v: '03 01 61', msg: 'protocol' },
    { v: 'a1 01 61', msg: 'url parser: unsupported' },
    { v: '00 00', msg: 'body' },
    { v: '10 ff 61 61 ', msg: 'bounds' },
    { v: '10 01 61 61 ', msg: 'bounds' },
  ]) {
    it(`ResourceLocator.parse() throws ${msg}`, () => {
      const hexValue = v.replace(/\s/g, '');
      const ab = hex.decodeArrayBuffer(hexValue);
      expect(() => ResourceLocator.parse(new Uint8Array(ab))).to.throw(msg);
    });
  }

  for (const { u, kid, msg } of [
    { u: 'gopher://a', kid: 'r1', msg: 'unsupported' },
    { u: 'https://', kid: 'r1', msg: 'empty' },
    { u: 'https://a', kid: '1234567890123456789012345678901234567890', msg: 'identifier length' },
  ]) {
    it(`invalid resource locator param throws ${msg}`, () => {
      expect(() => ResourceLocator.fromURL(u, kid)).throw(msg);
    });
  }
});
