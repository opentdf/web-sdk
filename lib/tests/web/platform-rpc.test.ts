import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';
import { PlatformClient } from '../../src/platform.js';

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
    const platform = new PlatformClient({
      authProvider,
      platformUrl,
    });

    try {
      const response = await platform.v1.wellknown.getWellKnownConfiguration({});
      expect(response.$typeName).to.equal(
        'wellknownconfiguration.GetWellKnownConfigurationResponse'
      );
    } catch (e) {
      expect.fail('Test failed missing method', e);
    }
  });

  it(`policy attribute method with Authorization headers`, async () => {
    const platform = new PlatformClient({
      authProvider,
      platformUrl,
    });

    try {
      const response = await platform.v1.attributes.listAttributes({});
      expect(response.$typeName).to.equal('policy.attributes.ListAttributesResponse');
    } catch (e) {
      expect.fail('Test failed missing auth headers', e);
    }
  });

  it(`list key access servers with Authorization headers`, async () => {
    const platform = new PlatformClient({
      authProvider,
      platformUrl,
    });

    try {
      const response = await platform.v1.keyAccessServerRegistry.listKeyAccessServers({});
      expect(response.$typeName).to.equal('policy.kasregistry.ListKeyAccessServersResponse');
    } catch (e) {
      expect.fail('Test failed missing auth headers', e);
    }
  });
});
