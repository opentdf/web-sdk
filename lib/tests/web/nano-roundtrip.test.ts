import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';

import { NanoTDFClient } from '../../src/nanoclients.js';
import NanoTDF from '../../src/nanotdf/NanoTDF.js';

const authProvider = <AuthProvider>{
  updateClientPublicKey: async () => {
    /* mocked function */
  },
  withCreds: async (req: HttpRequest): Promise<HttpRequest> =>
    withHeaders(req, {
      Authorization:
        'Bearer dummy-auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZGYiLCJzdWIiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.XFu4sQxAd6n-b7urqTdQ-I9zKqKSQtC04unHsMSpJjc',
    }),
};

const kasEndpoint = 'http://localhost:3000';

describe('Local roundtrip Tests', () => {
  for (const ecdsaBinding of [false, true]) {
    const bindingName = ecdsaBinding ? 'ecdsa' : 'gmac';
    it(`roundtrip string (${bindingName} policy binding)`, async () => {
      const client = new NanoTDFClient({ authProvider, kasEndpoint });
      const cipherText = await client.encrypt('hello world', { ecdsaBinding });
      const client2 = new NanoTDFClient({ authProvider, kasEndpoint });
      const nanotdfParsed = NanoTDF.from(cipherText);

      expect(nanotdfParsed.header.kas.url).to.equal(kasEndpoint);
      expect(nanotdfParsed.header.kas.identifier).to.equal('e1');

      const actual = await client2.decrypt(cipherText);
      expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
    });
  }
});
