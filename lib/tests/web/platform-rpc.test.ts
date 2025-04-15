import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';
import { OpenTDF } from '../../src/opentdf.js';

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

const platformUrl = 'http://localhost:3000';

describe('Local Platform Connect RPC Client Tests', () => {
  it(`wellknown configuration public rpc method`, async () => {
    const client = new OpenTDF({
      authProvider,
      platformUrl,
    });

    try {
      const response = await client.services.wellknown.getWellKnownConfiguration({});
      expect(response.$typeName).to.equal(
        'wellknownconfiguration.GetWellKnownConfigurationResponse'
      );
    } catch (e) {
      expect.fail('Test failed missing method');
    }
  });

  it(`policy attribute method with Authorization headers`, async () => {
    const client = new OpenTDF({
      authProvider,
      platformUrl,
    });

    try {
      const response = await client.services.attributes.listAttributes({});
      expect(response.$typeName).to.equal('policy.attributes.ListAttributesResponse');
    } catch (e) {
      expect.fail('Test failed missing auth headers');
    }
  });
});
