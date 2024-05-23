import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';

import { NanoTDFClient } from '../../src/index.js';
import { base64 } from '../../src/encodings/index.js';

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
  it('roundtrip string', async () => {
    const client = new NanoTDFClient({ authProvider, kasEndpoint });
    const cipherText = await client.encrypt('hello world');
    const client2 = new NanoTDFClient({ authProvider, kasEndpoint });
    const actual = await client2.decrypt(cipherText);
    expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
  });
  it.skip('golden file', async() => {
    const cipherText = base64.decodeArrayBuffer('TDFMAA5sb2NhbGhvc3Q6ODA4MAABAgBomFyjdwuth2kHU14YckzIfjPZPU8TngPzQhCDZDzPrmPGrm0jGkuPGsRah6BscTLKpvPXT615SiY4FVmyiACSB46i0tzJpGOf857L4YrGekm31J0xq9MwC3CjQIKGW++jU/T9UMXDg2ERg2xBNG95tALlcFEj0emTOXJLX50tA2YzDS6N3941+Pv9RbankFUNEAAAG9U8wgL2p0jify5PQx0kFjvmUZW1VcXjhGw+2g==')
    const client = new NanoTDFClient({ authProvider, kasEndpoint, kasAliases: {'http://localhost:8080': 'http://localhost:3000'} });
    const actual = await client.decrypt(cipherText);
    expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
  });
});

