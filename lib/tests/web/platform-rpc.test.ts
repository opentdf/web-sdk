import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';
import { PlatformClient } from '../../src/platform.js';
import { attributeFQNsAsValues } from '../../src/policy/api.js';
import { fetchWrappedKey } from '../../src/access/access-rpc.js';
import { PermissionDeniedError } from '../../src/errors.js';

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

function authProviderWithHeaders(headers: Record<string, string>): AuthProvider {
  return <AuthProvider>{
    updateClientPublicKey: async () => {
      /* mocked function */
    },
    withCreds: async (req: HttpRequest): Promise<HttpRequest> =>
      withHeaders(req, {
        Authorization:
          'Bearer dummy-auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZGYiLCJzdWIiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.XFu4sQxAd6n-b7urqTdQ-I9zKqKSQtC04unHsMSpJjc',
        ...headers,
      }),
  };
}

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

  it(`policy attribute method with auth`, async () => {
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

  it(`list key access servers with auth`, async () => {
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

  it(`list fqns by attribute value with auth`, async () => {
    const platform = new PlatformClient({
      authProvider,
      platformUrl,
    });

    const fqns = ['https://granted.ns/attr/granted/value/granted'];

    try {
      const response = await platform.v1.attributes.getAttributeValuesByFqns({
        fqns,
      });
      expect(response.$typeName).to.equal('policy.attributes.GetAttributeValuesByFqnsResponse');
    } catch (e) {
      expect.fail('Test failed missing auth headers', e);
    }
  });

  it(`attributeFQNsAsValues value with auth from api`, async () => {
    const fqns = ['https://granted.ns/attr/granted/value/granted'];

    try {
      const response = await attributeFQNsAsValues(platformUrl, authProvider, ...fqns);
      expect(response[0].$typeName).to.equal('policy.Value');
    } catch (e) {
      expect.fail('Test failed missing auth headers', e);
    }
  });

  it(`rewrap key with auth`, async () => {
    const platform = new PlatformClient({
      authProvider,
      platformUrl,
    });

    try {
      const response = await platform.v1.access.rewrap({
        // {"requestBody": "mock-request-body"}
        signedRequestToken:
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyZXF1ZXN0Qm9keSI6Im1vY2stcmVxdWVzdC1ib2R5In0.0O9eyg-zC5Ztf78mPaa61n6INtpTdJv6iQQ_3tg2TRlzA73Md-JDTedGKwQ_J6QQycR5AMY5UqrsQvkcK50jfQ',
      });
      expect(response.$typeName).to.equal('kas.RewrapResponse');
    } catch (e) {
      expect.fail('Test failed missing auth headers', e);
    }
  });

  it(`rewrap key with requiredobligations in error`, async () => {
    try {
      const ap = authProviderWithHeaders({
        'x-test-response': '403',
        'x-test-required-obligations':
          '["https://example.com/obl/obligation1","https://example.com/obl/obligation2"]',
      });
      try {
        await fetchWrappedKey(
          `${platformUrl}/`,
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyZXF1ZXN0Qm9keSI6Im1vY2stcmVxdWVzdC1ib2R5In0.0O9eyg-zC5Ztf78mPaa61n6INtpTdJv6iQQ_3tg2TRlzA73Md-JDTedGKwQ_J6QQycR5AMY5UqrsQvkcK50jfQ',
          ap
        );
        expect.fail('Test should have thrown PermissionDeniedError');
      } catch (e) {
        expect(e).to.be.instanceOf(PermissionDeniedError);
        const pde = e as PermissionDeniedError;
        expect(pde.requiredObligations).to.deep.equal([
          'https://example.com/obl/obligation1',
          'https://example.com/obl/obligation2',
        ]);
      }
    } catch (e) {
      console.log(e);
    }
  });
});
