import { readFile } from '@web/test-runner-commands';
import { expect } from '@esm-bundle/chai';
import { NanoTDF } from '../../src/nanotdf/index.js';

describe('NanoTDF work with various sizes', async () => {
  /**
   * This test came out of a discovery that there were miscalculations on the payload length and
   * the max payload length.
   *
   * FIXME: Improve test to add value outside of immediate solution.
   */
  it('should decrypt files larger than a few bytes ', async () => {
    // NOTE readFile only supports strings :-/
    const nanotdfWideString = await readFile({
      path: '../../../../src/__fixtures__/dummy.txt.ntdf',
      encoding: 'binary',
    });
    if (!nanotdfWideString) {
      throw new Error();
    }
    const { length } = nanotdfWideString;
    const buffer = new ArrayBuffer(length);
    const bufferView = new Uint8Array(buffer);
    for (let i = 0; i < length; i++) {
      bufferView[i] = nanotdfWideString.charCodeAt(i);
    }

    const ntdf = NanoTDF.from(bufferView, undefined, true);
    expect(ntdf.payload.ciphertextWithAuthTag.byteLength).to.eql(65533);
  });
});
