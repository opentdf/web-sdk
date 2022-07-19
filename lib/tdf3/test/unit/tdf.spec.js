import { expect } from 'chai';

import { TDF } from '../../src';

describe('TDF', () => {
  it('constructs', () => {
    const actual = new TDF();
    expect(actual).to.be.an.instanceof(TDF);
  });

  it('creates', () => {
    const actual = TDF.create();
    expect(actual).to.be.an.instanceof(TDF);
  });

  it('Encodes the postMessage origin properly in wrapHtml', () => {
    const cipherText = 'abcezas123';
    const transferUrl = 'https://local.virtru.com/start?htmlProtocol=1';
    const wrapped = TDF.wrapHtml(cipherText, JSON.stringify({ thisIs: 'metadata' }), transferUrl);
    const rawHtml = wrapped.toString();
    expect(rawHtml).to.include("'https://local.virtru.com', [channel.port2]);");
  });

  it('Round Trip wrapHtml and unwrapHtml', () => {
    const cipherText = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2]);
    const transferUrl = 'https://local.virtru.com/start?htmlProtocol=1';
    const wrapped = TDF.wrapHtml(cipherText, JSON.stringify({ thisIs: 'metadata' }), transferUrl);
    const unwrapped = TDF.unwrapHtml(wrapped);
    expect(unwrapped).to.eql(cipherText);
  });
});
