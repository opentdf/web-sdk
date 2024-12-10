import { expect } from '@esm-bundle/chai';
import { fromString } from '../../src/seekable.js';

describe('seekable tests', () => {
  it('seekable from string', async () => {
    const chunker = fromString('hello world');
    const actual = await chunker();
    expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
  });
});
