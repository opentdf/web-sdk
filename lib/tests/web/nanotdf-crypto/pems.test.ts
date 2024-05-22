import { expect } from '@esm-bundle/chai';

import { pemPublicToCrypto } from '../../../src/keyport/raw.js';

const ecPublic = `‌-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgUcv//GdNu1VQmcVj/LQGI5y/Ymo
/9UpCTTQTrhwTudNoYQ778vkBKHkDrkP1Q/aBi/POBODnKeaDv47Rq2PBg==
-----END PUBLIC KEY-----`;

describe('pemPublicToCrypto', () => {
  it('decode', async () => {
    const k = await pemPublicToCrypto(ecPublic);
    expect(k).to.deep.equal('hey');
  });
});
