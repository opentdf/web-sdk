import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';
import getMocks from '../mocks/index.js';


describe('keyAgreement', () => {
  it('golden', async () => {
    const Mocks = getMocks();
    const nanoPublicKey = await crypto.subtle.importKey(
      'raw',
      Mocks.ephemeralPublicKey,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      []
    );
    expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
  });
});

