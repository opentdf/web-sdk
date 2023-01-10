import { expect } from '@esm-bundle/chai';
import sinon from 'sinon';
import { AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';

import { NanoTDFClient } from '../../src/index.js';

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

const kasPubKey = `-----BEGIN CERTIFICATE-----
MIIBcjCCARegAwIBAgIUHeLWauo8LkzzWtq3alLWzR9Gxt4wCgYIKoZIzj0EAwIw
DjEMMAoGA1UEAwwDa2FzMB4XDTIyMDMwMzE0NDcwMFoXDTIzMDMwMzE0NDcwMFow
DjEMMAoGA1UEAwwDa2FzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEoPCmh6d
boMZLjFLX6Q3gLsiV40e1fpJ9gfm8GXogh0w7c8bb3SkNH4NXZ0YpevkScy2UZOl
KIgSAn70lERIj6NTMFEwHQYDVR0OBBYEFAHmNbtdve05mTWKmHLiTSG49oL1MB8G
A1UdIwQYMBaAFAHmNbtdve05mTWKmHLiTSG49oL1MA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSQAwRgIhALJmwqc6xYQKu84GOjz+P4WmBHEoGvqT2ZWXnLuZ
5jKMAiEAmdiam2/jiDTt38PKQkkJvqTlOogTMnigGBOE+FuuB2M=
-----END CERTIFICATE-----`;

function mockApiResponse(status = 200, body = {}) {
  return new globalThis.Response(JSON.stringify(body), {
    status,
    headers: { 'Content-type': 'application/json' },
  });
}

function initSandbox() {
  const sandbox = sinon.createSandbox();
  const fetchLives = sandbox.stub(globalThis, 'fetch');
  fetchLives.callsFake(async (resource, init) => {
    if (resource === 'http://localhost:65432/api/kas/kas_public_key?algorithm=ec:secp256r1') {
      return mockApiResponse(200, kasPubKey);
    }
    console.log(`trying to fetch( resource: [${resource}], init:`, init);
    return mockApiResponse(404);
  });
  return sandbox;
}

const kasUrl = 'http://localhost:65432/api/kas';

describe('Local roundtrip Tests', () => {
  it('roundtrip string', async () => {
    // const sandbox = initSandbox();
    const sandbox = initSandbox();
    try {
      const client = new NanoTDFClient(authProvider, kasUrl);
      const keyAgreementSpy = sandbox.spy(globalThis.crypto.subtle, 'deriveKey');
      sandbox.stub(client, 'rewrapKey').callsFake(async () => keyAgreementSpy.lastCall.returnValue);
      const cipherText = await client.encrypt('hello world');
      const actual = await client.decrypt(cipherText);
      expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
    } finally {
      sandbox.reset();
    }
  });
});
