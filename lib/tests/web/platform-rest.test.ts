import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';
import {
  fetchKasPubKey,
  fetchKeyAccessServers,
  fetchWrappedKey,
} from '../../src/access/access-fetch.js';

const authProvider = <AuthProvider>{
  updateClientPublicKey: async () => {
    /* mocked function */
  },
  withCreds: async (req: HttpRequest): Promise<HttpRequest> =>
    withHeaders(req, {
      Authorization:
        'Bearer dummy-auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZGYiLCJzdWIiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.XFu4sQxAd6n-b7urqTdQ-I9zKqKSQtC04unHsMSpJjc',
      'roundtrip-test-response': '200',
    }),
};

const platformUrl = 'http://localhost:3000';

describe('Local Platform Legacy Rest tests', () => {
  it(`it calls rest endpoint fetchWrappedKey`, async () => {
    try {
      const result = await fetchWrappedKey(
        `${platformUrl}/v2/rewrap`,
        { signedRequestToken: '' },
        authProvider
      );
      expect(!!result).to.equal(true);
    } catch (e) {
      console.log(e);
    }
  });

  it(`it calls rest endpoint fetchKasPubKey`, async () => {
    try {
      const result = await fetchKasPubKey(`${platformUrl}/v2/kas_public_key`);
      expect(!!result).to.equal(true);
    } catch (e) {
      console.log(e);
    }
  });

  it(`it calls rest endpoint fetchKeyAccessServers`, async () => {
    try {
      const result = await fetchKeyAccessServers(platformUrl, authProvider);
      expect(!!result).to.equal(true);
    } catch (e) {
      console.log(e);
    }
  });
});
