import { expect } from 'chai';

import { setRemoteStoreAsStream } from '../src/index.js';

describe('setRemoteStoreAsStream', () => {
  it('is a function', () => {
    expect(typeof setRemoteStoreAsStream).to.equal('function');
  });
});
