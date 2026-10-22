import { expect } from '@esm-bundle/chai';

import { crc32Backend, unsigned } from '../../../tdf3/src/utils/buffer-crc32.js';

describe('CRC-32 in the browser', function () {
  it('falls back to the portable implementation', function () {
    expect(crc32Backend).to.equal('portable');
  });

  it('matches the standard check value, in one call or two', function () {
    const data = new TextEncoder().encode('123456789');
    expect(unsigned(data, 0)).to.equal(0xcbf43926);
    expect(unsigned(data.subarray(5), unsigned(data.subarray(0, 5), 0))).to.equal(0xcbf43926);
  });
});
