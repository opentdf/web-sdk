import { expect } from '@esm-bundle/chai';
import { clientSecretAuthProvider } from '../../../src/auth/providers.js';
import { globalNonceCache } from '../../../src/auth/dpop-nonce.js';
import { PlatformClient } from '../../../src/platform.js';
import { generateSigningKeyPair } from '../../../tdf3/src/crypto/index.js';
import type { KeyPair } from '../../../tdf3/src/crypto/declarations.js';

const SERVER_ORIGIN = 'http://localhost:3000';
const TOKEN_URL = `${SERVER_ORIGIN}/protocol/openid-connect/token`;
// Fixed nonce issued by the mock server's resource-server (RPC) endpoints.
const RS_NONCE = 'dpop-test-rs-nonce-xyz';

/**
 * Browser-side counterpart to tests/mocha/dpop-rpc-nonce.spec.ts: exercises the
 * Connect-RPC DPoP-Nonce challenge retry through the connect-web transport that
 * the browser SDK actually uses. See that file for the full rationale.
 */
describe('DPoP RS nonce retry over Connect-RPC (browser)', () => {
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

    const response = await platform.v1.keyAccessServerRegistry.listKeyAccessServers({});

    expect(response.$typeName).to.equal('policy.kasregistry.ListKeyAccessServersResponse');
    expect(response.keyAccessServers.map((s) => s.uri)).to.include(SERVER_ORIGIN);
    expect(globalNonceCache.get(SERVER_ORIGIN)).to.equal(RS_NONCE);
  });
});
