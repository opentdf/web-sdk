import { expect } from 'chai';
import { AccessToken } from '../../src/auth/oidc.js';
import { clientSecretAuthProvider } from '../../src/auth/providers.js';
import { globalNonceCache } from '../../src/auth/dpop-nonce.js';
import { DefaultCryptoService, generateSigningKeyPair } from '../../tdf3/src/crypto/index.js';
import type { KeyPair } from '../../tdf3/src/crypto/declarations.js';

const SERVER_ORIGIN = 'http://localhost:3000';
const TOKEN_URL = `${SERVER_ORIGIN}/protocol/openid-connect/token`;
// Fixed nonce issued by server.ts /protocol/openid-connect/token endpoint
const SERVER_NONCE = 'dpop-test-nonce-abc';

describe('DPoP nonce challenge — integration with mock server', function (this: Mocha.Suite) {
  this.timeout(10_000);

  let keyPair: KeyPair;

  before(async () => {
    keyPair = await generateSigningKeyPair();
  });

  afterEach(() => {
    globalNonceCache.clearAll();
  });

  it('transparently retries with server-issued nonce and returns 200', async () => {
    const accessToken = new AccessToken(
      {
        clientId: 'test-client',
        clientSecret: 'test-secret',
        exchange: 'client',
        oidcOrigin: SERVER_ORIGIN,
        dpopEnabled: true,
        signingKey: keyPair,
      },
      DefaultCryptoService
      // No fetch override: uses global fetch (Node 18+) against the real server
    );

    // doPost sends the initial request (no nonce), gets 401 + DPoP-Nonce,
    // then automatically retries with the nonce and receives 200.
    const response = await accessToken.doPost(TOKEN_URL, {
      grant_type: 'client_credentials',
      client_id: 'test-client',
      client_secret: 'test-secret',
    });

    expect(response.status).to.equal(200);
    const body = (await response.json()) as { access_token: string };
    expect(body.access_token).to.equal('test-dpop-token');

    // Cache must be populated with the server's nonce after the round-trip
    expect(globalNonceCache.get(SERVER_ORIGIN)).to.equal(SERVER_NONCE);
  });

  it('uses cached nonce on the first request after a prior successful challenge', async () => {
    // Pre-seed cache as if a prior request already populated it
    globalNonceCache.set(SERVER_ORIGIN, SERVER_NONCE);

    const accessToken = new AccessToken(
      {
        clientId: 'test-client',
        clientSecret: 'test-secret',
        exchange: 'client',
        oidcOrigin: SERVER_ORIGIN,
        dpopEnabled: true,
        signingKey: keyPair,
      },
      DefaultCryptoService
    );

    // With the correct nonce already cached, the first request should succeed directly (no retry).
    const response = await accessToken.doPost(TOKEN_URL, {
      grant_type: 'client_credentials',
      client_id: 'test-client',
      client_secret: 'test-secret',
    });

    expect(response.status).to.equal(200);
  });

  it('initial token fetch via clientSecretAuthProvider includes DPoP proof after updateClientPublicKey', async () => {
    // Mirrors the CLI path: provider is created without DPoP awareness, then a
    // DPoP key is bound via updateClientPublicKey. The very next token POST
    // must carry a DPoP header (RFC 9449 §5) and survive the nonce challenge.
    const provider = await clientSecretAuthProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: SERVER_ORIGIN,
      oidcTokenEndpoint: TOKEN_URL,
      exchange: 'client',
    });
    await provider.updateClientPublicKey(keyPair);

    const token = await provider.oidcAuth.get(false);
    expect(token).to.equal('test-dpop-token');
    expect(globalNonceCache.get(SERVER_ORIGIN)).to.equal(SERVER_NONCE);
  });
});
