import { expect } from '@esm-bundle/chai';
import { fake, replace, restore } from 'sinon';
import {
  clientCredentialsTokenProvider,
  refreshTokenProvider,
  externalJwtTokenProvider,
} from '../../src/auth/token-providers.js';

// Helper: create a fake JWT with a given exp claim
function fakeJwt(exp: number): string {
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ sub: 'test', exp }));
  return `${header}.${payload}.fake-signature`;
}

// Helper: create a mock fetch that returns token responses
function mockFetch(
  responses: Array<{ access_token: string; refresh_token?: string; expires_in?: number }>
) {
  let callIndex = 0;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const fetchFake = fake(async (_url: string, _opts?: RequestInit) => {
    const resp = responses[callIndex] ?? responses[responses.length - 1];
    callIndex++;
    return new Response(JSON.stringify(resp), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  });
  replace(globalThis, 'fetch', fetchFake as typeof fetch);
  return fetchFake;
}

// Helper: create a mock fetch that returns an error response, then succeeds
function mockFetchWithError(
  errorStatus: number,
  successResponse: { access_token: string; refresh_token?: string }
) {
  let callIndex = 0;
  const fetchFake = fake(async () => {
    callIndex++;
    if (callIndex === 1) {
      return new Response('token request failed', {
        status: errorStatus,
        statusText: 'Error',
      });
    }
    return new Response(JSON.stringify(successResponse), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  });
  replace(globalThis, 'fetch', fetchFake as typeof fetch);
  return fetchFake;
}

describe('clientCredentialsTokenProvider', () => {
  afterEach(() => restore());

  it('fetches a token with client_credentials grant', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token }]);

    const provider = clientCredentialsTokenProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const result = await provider();
    expect(result).to.equal(token);
    expect(fetchFake.callCount).to.equal(1);

    const [url, opts] = fetchFake.firstCall.args;
    expect(url).to.equal('http://localhost:8080/auth/realms/opentdf/protocol/openid-connect/token');
    const body = (opts as RequestInit).body as string;
    expect(body).to.include('grant_type=client_credentials');
    expect(body).to.include('client_id=test-client');
    expect(body).to.include('client_secret=test-secret');
  });

  it('caches the token on subsequent calls', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token }]);

    const provider = clientCredentialsTokenProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    await provider();
    await provider();
    await provider();
    expect(fetchFake.callCount).to.equal(1);
  });

  it('refreshes when token is expired', async () => {
    const expiredToken = fakeJwt(Date.now() / 1000 - 60);
    const freshToken = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: expiredToken }, { access_token: freshToken }]);

    const provider = clientCredentialsTokenProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const first = await provider();
    expect(first).to.equal(expiredToken);

    const second = await provider();
    expect(second).to.equal(freshToken);
    expect(fetchFake.callCount).to.equal(2);
  });

  it('uses custom token endpoint when provided', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token }]);

    const provider = clientCredentialsTokenProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
      oidcTokenEndpoint: 'http://custom-endpoint/token',
    });

    await provider();
    const [url] = fetchFake.firstCall.args;
    expect(url).to.equal('http://custom-endpoint/token');
  });

  it('throws on missing clientId', () => {
    expect(() =>
      clientCredentialsTokenProvider({
        clientId: '',
        clientSecret: 'secret',
        oidcOrigin: 'http://localhost:8080',
      })
    ).to.throw('clientId and clientSecret are required');
  });

  it('throws on blank oidcOrigin without endpoint override', () => {
    expect(() =>
      clientCredentialsTokenProvider({
        clientId: 'test-client',
        clientSecret: 'secret',
        oidcOrigin: '',
      })
    ).to.throw('oidcOrigin or oidcTokenEndpoint is required');
  });

  it('caches opaque tokens using expires_in', async () => {
    const fetchFake = mockFetch([{ access_token: 'opaque-token-abc', expires_in: 3600 }]);

    const provider = clientCredentialsTokenProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const first = await provider();
    const second = await provider();
    expect(first).to.equal('opaque-token-abc');
    expect(second).to.equal('opaque-token-abc');
    expect(fetchFake.callCount).to.equal(1);
  });

  it('deduplicates concurrent calls', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token }]);

    const provider = clientCredentialsTokenProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const [r1, r2, r3] = await Promise.all([provider(), provider(), provider()]);
    expect(r1).to.equal(token);
    expect(r2).to.equal(token);
    expect(r3).to.equal(token);
    expect(fetchFake.callCount).to.equal(1);
  });

  it('rejects on error response and allows retry', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetchWithError(401, { access_token: token });

    const provider = clientCredentialsTokenProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    try {
      await provider();
      expect.fail('should have thrown');
    } catch (e) {
      expect((e as Error).message).to.include('401');
    }

    // Retry should succeed
    const result = await provider();
    expect(result).to.equal(token);
    expect(fetchFake.callCount).to.equal(2);
  });
});

describe('refreshTokenProvider', () => {
  afterEach(() => restore());

  it('exchanges refresh token on first call', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token, refresh_token: 'new-refresh' }]);

    const provider = refreshTokenProvider({
      clientId: 'test-client',
      refreshToken: 'initial-refresh',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const result = await provider();
    expect(result).to.equal(token);

    const body = (fetchFake.firstCall.args[1] as RequestInit).body as string;
    expect(body).to.include('grant_type=refresh_token');
    expect(body).to.include('refresh_token=initial-refresh');
  });

  it('uses updated refresh token on subsequent calls', async () => {
    const expiredToken = fakeJwt(Date.now() / 1000 - 60);
    const freshToken = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([
      { access_token: expiredToken, refresh_token: 'refresh-v2' },
      { access_token: freshToken, refresh_token: 'refresh-v3' },
    ]);

    const provider = refreshTokenProvider({
      clientId: 'test-client',
      refreshToken: 'refresh-v1',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    await provider();
    await provider();
    expect(fetchFake.callCount).to.equal(2);

    const secondBody = (fetchFake.secondCall.args[1] as RequestInit).body as string;
    expect(secondBody).to.include('refresh_token=refresh-v2');
  });

  it('deduplicates concurrent refresh calls', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token, refresh_token: 'new-refresh' }]);

    const provider = refreshTokenProvider({
      clientId: 'test-client',
      refreshToken: 'initial-refresh',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const [r1, r2] = await Promise.all([provider(), provider()]);
    expect(r1).to.equal(token);
    expect(r2).to.equal(token);
    expect(fetchFake.callCount).to.equal(1);
  });

  it('rejects on error response and allows retry', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetchWithError(500, { access_token: token, refresh_token: 'new-refresh' });

    const provider = refreshTokenProvider({
      clientId: 'test-client',
      refreshToken: 'initial-refresh',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    try {
      await provider();
      expect.fail('should have thrown');
    } catch (e) {
      expect((e as Error).message).to.include('500');
    }

    const result = await provider();
    expect(result).to.equal(token);
    expect(fetchFake.callCount).to.equal(2);
  });
});

describe('externalJwtTokenProvider', () => {
  afterEach(() => restore());

  it('performs token exchange on first call', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token, refresh_token: 'new-refresh' }]);

    const provider = externalJwtTokenProvider({
      clientId: 'test-client',
      externalJwt: 'eyJhbGciOi...',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const result = await provider();
    expect(result).to.equal(token);

    const body = (fetchFake.firstCall.args[1] as RequestInit).body as string;
    expect(body).to.include('grant_type=urn');
    expect(body).to.include('token-exchange');
    expect(body).to.include('subject_token=eyJhbGciOi');
  });

  it('uses refresh token for subsequent calls after initial exchange', async () => {
    const expiredToken = fakeJwt(Date.now() / 1000 - 60);
    const freshToken = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([
      { access_token: expiredToken, refresh_token: 'exchange-refresh' },
      { access_token: freshToken },
    ]);

    const provider = externalJwtTokenProvider({
      clientId: 'test-client',
      externalJwt: 'eyJhbGciOi...',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    await provider();
    await provider();

    const secondBody = (fetchFake.secondCall.args[1] as RequestInit).body as string;
    expect(secondBody).to.include('grant_type=refresh_token');
    expect(secondBody).to.include('refresh_token=exchange-refresh');
  });

  it('deduplicates concurrent exchange calls', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetch([{ access_token: token, refresh_token: 'new-refresh' }]);

    const provider = externalJwtTokenProvider({
      clientId: 'test-client',
      externalJwt: 'eyJhbGciOi...',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    const [r1, r2] = await Promise.all([provider(), provider()]);
    expect(r1).to.equal(token);
    expect(r2).to.equal(token);
    expect(fetchFake.callCount).to.equal(1);
  });

  it('rejects on error response and allows retry', async () => {
    const token = fakeJwt(Date.now() / 1000 + 3600);
    const fetchFake = mockFetchWithError(403, { access_token: token, refresh_token: 'new-refresh' });

    const provider = externalJwtTokenProvider({
      clientId: 'test-client',
      externalJwt: 'eyJhbGciOi...',
      oidcOrigin: 'http://localhost:8080/auth/realms/opentdf',
    });

    try {
      await provider();
      expect.fail('should have thrown');
    } catch (e) {
      expect((e as Error).message).to.include('403');
    }

    const result = await provider();
    expect(result).to.equal(token);
    expect(fetchFake.callCount).to.equal(2);
  });
});
