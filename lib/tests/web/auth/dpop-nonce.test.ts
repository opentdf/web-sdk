import { expect } from '@esm-bundle/chai';
import { stub } from 'sinon';
import { AccessToken } from '../../../src/auth/oidc.js';
import { globalNonceCache } from '../../../src/auth/dpop-nonce.js';
import { authTokenDPoPInterceptor } from '../../../src/auth/interceptors.js';
import { DefaultCryptoService, generateSigningKeyPair } from '../../../tdf3/src/crypto/index.js';
import type { KeyPair } from '../../../tdf3/src/crypto/declarations.js';

/** Decode JWT payload without verification (base64url → JSON). */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const b64 = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '=');
  return JSON.parse(atob(padded));
}

// ── AccessToken.doPost nonce retry ──────────────────────────────────────────

describe('AccessToken.doPost DPoP-Nonce retry', () => {
  const ORIGIN = 'http://localhost:3000';
  const TOKEN_URL = `${ORIGIN}/protocol/openid-connect/token`;
  const NONCE = 'server-nonce-xyz';

  let keyPair: KeyPair;

  before(async () => {
    keyPair = await generateSigningKeyPair();
  });

  afterEach(() => {
    globalNonceCache.clearAll();
  });

  function makeAccessToken(fetchStub: typeof fetch) {
    return new AccessToken(
      {
        clientId: 'test-client',
        clientSecret: 'test-secret',
        exchange: 'client',
        oidcOrigin: ORIGIN,
        dpopEnabled: true,
        signingKey: keyPair,
      },
      DefaultCryptoService,
      fetchStub
    );
  }

  it('retries with nonce when server responds 401 with DPoP-Nonce header', async () => {
    const fetchStub = stub();
    // First call: 401 challenge with DPoP-Nonce header
    fetchStub.onFirstCall().resolves({
      status: 401,
      ok: false,
      headers: new Headers({ 'DPoP-Nonce': NONCE }),
    } as Response);
    // Second call: 200 success
    fetchStub.onSecondCall().resolves({
      status: 200,
      ok: true,
      headers: new Headers(),
      json: stub().resolves({ access_token: 'test-token' }),
    } as unknown as Response);

    const accessToken = makeAccessToken(fetchStub as unknown as typeof fetch);
    const result = await accessToken.doPost(TOKEN_URL, { grant_type: 'client_credentials' });

    expect(fetchStub.callCount).to.equal(2);
    expect(result.status).to.equal(200);
    expect(globalNonceCache.get(ORIGIN)).to.equal(NONCE);

    // Second request's DPoP proof must include the nonce
    const secondInit = fetchStub.secondCall.args[1] as RequestInit;
    const secondHeaders = secondInit.headers as Record<string, string>;
    const retryPayload = decodeJwtPayload(secondHeaders['DPoP']);
    expect(retryPayload.nonce).to.equal(NONCE);
  });

  it('does not retry when server returns the same nonce already cached', async () => {
    // Pre-seed the cache with the same nonce the server will return
    globalNonceCache.set(ORIGIN, NONCE);

    const fetchStub = stub().resolves({
      status: 401,
      ok: false,
      headers: new Headers({ 'DPoP-Nonce': NONCE }),
    } as Response);

    const accessToken = makeAccessToken(fetchStub as unknown as typeof fetch);
    const result = await accessToken.doPost(TOKEN_URL, { grant_type: 'client_credentials' });

    // No retry — same nonce means we'd loop; return the 401 to the caller
    expect(fetchStub.callCount).to.equal(1);
    expect(result.status).to.equal(401);
  });
});

// ── authTokenDPoPInterceptor nonce retry ────────────────────────────────────

describe('authTokenDPoPInterceptor DPoP-Nonce retry', () => {
  const ORIGIN = 'http://localhost:3000';
  const REQUEST_URL = `${ORIGIN}/kas.AccessService/Rewrap`;
  const NONCE = 'interceptor-nonce-abc';

  let keyPair: KeyPair;

  before(async () => {
    keyPair = await generateSigningKeyPair();
  });

  afterEach(() => {
    globalNonceCache.clearAll();
  });

  function makeInterceptor() {
    return authTokenDPoPInterceptor({
      tokenProvider: async () => 'dummy-access-token',
      dpopKeys: Promise.resolve(keyPair),
    });
  }

  function makeMockReq() {
    return { header: new Headers(), url: REQUEST_URL } as Parameters<
      ReturnType<ReturnType<typeof authTokenDPoPInterceptor>>
    >[0];
  }

  it('retries with nonce when interceptor catches a code-16 error with dpop-nonce metadata', async () => {
    const mockNext = stub();
    // First call: simulate server rejecting with Unauthenticated + dpop-nonce metadata
    mockNext.onFirstCall().callsFake(() =>
      Promise.reject({
        code: 16,
        metadata: { get: (k: string) => (k === 'dpop-nonce' ? NONCE : null) },
      })
    );
    // Second call: success
    mockNext.onSecondCall().resolves({ header: { get: () => null } });

    const interceptor = makeInterceptor();
    await interceptor(mockNext as Parameters<typeof interceptor>[0])(makeMockReq());

    expect(mockNext.callCount).to.equal(2);
    expect(globalNonceCache.get(ORIGIN)).to.equal(NONCE);

    // Retry request must have nonce in its DPoP proof
    const retryReq = mockNext.secondCall.firstArg as { header: Headers };
    const retryDpopJwt = retryReq.header.get('DPoP')!;
    const retryPayload = decodeJwtPayload(retryDpopJwt);
    expect(retryPayload.nonce).to.equal(NONCE);
  });

  it('does not retry when server returns the same nonce already cached', async () => {
    globalNonceCache.set(ORIGIN, NONCE);

    const mockNext = stub().callsFake(() =>
      Promise.reject({
        code: 16,
        metadata: { get: (k: string) => (k === 'dpop-nonce' ? NONCE : null) },
      })
    );

    const interceptor = makeInterceptor();
    try {
      await interceptor(mockNext as Parameters<typeof interceptor>[0])(makeMockReq());
      expect.fail('should have thrown');
    } catch (err) {
      // Expected: interceptor re-throws when nonce unchanged
    }

    expect(mockNext.callCount).to.equal(1);
  });
});
