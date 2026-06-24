import { expect } from 'chai';
import { clientSecretAuthProvider } from '../../src/auth/providers.js';
import { globalNonceCache } from '../../src/auth/dpop-nonce.js';
import { PlatformClient } from '../../src/platform.js';
import { generateSigningKeyPair } from '../../tdf3/src/crypto/index.js';
import type { KeyPair } from '../../tdf3/src/crypto/declarations.js';

const SERVER_ORIGIN = 'http://localhost:3000';
const TOKEN_URL = `${SERVER_ORIGIN}/protocol/openid-connect/token`;
// Fixed nonce issued by the mock server's resource-server (RPC) endpoints.
const RS_NONCE = 'dpop-test-rs-nonce-xyz';

/**
 * End-to-end regression for the Connect-RPC DPoP-Nonce challenge retry.
 *
 * Drives a real PlatformClient (Connect transport) through a DPoP auth provider
 * against the mock server so `ListKeyAccessServers` issues an RS nonce challenge
 * and the `authProviderInterceptor` must catch the ConnectError, cache the nonce,
 * re-sign, and retry once. Before that interceptor fix the first call rejected
 * with a Code.Unauthenticated ConnectError — exactly the bug that reached xtest
 * (`test_dpop_server_issued_nonce_retry`).
 */
describe('DPoP RS nonce retry over Connect-RPC — integration with mock server', function (this: Mocha.Suite) {
  this.timeout(10_000);

  let keyPair: KeyPair;

  before(async () => {
    keyPair = await generateSigningKeyPair();
  });

  afterEach(() => {
    globalNonceCache.clearAll();
  });

  it('ListKeyAccessServers: interceptor retries once on the RS nonce challenge and succeeds', async () => {
    const authProvider = await clientSecretAuthProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: SERVER_ORIGIN,
      oidcTokenEndpoint: TOKEN_URL,
      exchange: 'client',
      dpopEnabled: true,
      signingKey: keyPair,
    });

    const platform = new PlatformClient({ authProvider, platformUrl: SERVER_ORIGIN });

    // No RS nonce is cached for this origin yet: the first proof carries the
    // wrong (or no) nonce, the server challenges with the RS nonce, and the
    // interceptor must retry once for this call to resolve.
    const response = await platform.v1.keyAccessServerRegistry.listKeyAccessServers({});

    expect(response.$typeName).to.equal('policy.kasregistry.ListKeyAccessServersResponse');
    expect(response.keyAccessServers.map((s) => s.uri)).to.include(SERVER_ORIGIN);

    // The consumed challenge leaves the RS nonce cached for the origin, proving
    // a challenge happened and the retry adopted it.
    expect(globalNonceCache.get(SERVER_ORIGIN)).to.equal(RS_NONCE);
  });
});
