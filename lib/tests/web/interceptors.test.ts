import { expect } from '@esm-bundle/chai';
import { type Interceptor } from '@connectrpc/connect';
import type { AuthProvider } from '../../src/auth/auth.js';
import { HttpRequest, withHeaders } from '../../src/auth/auth.js';
import {
  authTokenInterceptor,
  authTokenDPoPInterceptor,
  authProviderInterceptor,
  resolveInterceptors,
  resolveAuthConfig,
  isInterceptorConfig,
} from '../../src/auth/interceptors.js';

// --- helpers ---

/** Runs an interceptor and captures the headers it sets on the request. */
async function captureHeaders(
  interceptor: Interceptor,
  url = 'https://example.com/v1/test'
): Promise<Headers> {
  const headers = new Headers();
  const mockReq = { header: headers, url } as Parameters<ReturnType<Interceptor>>[0];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mockNext = async (req: any) => req as any;
  await interceptor(mockNext)(mockReq);
  return headers;
}

// --- authTokenInterceptor ---

describe('authTokenInterceptor', () => {
  it('sets the Authorization header with the token from tokenProvider', async () => {
    const interceptor = authTokenInterceptor(async () => 'test-token-123');
    const headers = await captureHeaders(interceptor);
    expect(headers.get('Authorization')).to.equal('Bearer test-token-123');
  });

  it('calls tokenProvider on each request', async () => {
    let callCount = 0;
    const interceptor = authTokenInterceptor(async () => {
      callCount++;
      return `token-${callCount}`;
    });

    const h1 = await captureHeaders(interceptor);
    const h2 = await captureHeaders(interceptor);

    expect(h1.get('Authorization')).to.equal('Bearer token-1');
    expect(h2.get('Authorization')).to.equal('Bearer token-2');
    expect(callCount).to.equal(2);
  });
});

// --- authTokenDPoPInterceptor ---

describe('authTokenDPoPInterceptor', () => {
  it('sets Authorization, DPoP, and X-VirtruPubKey headers', async () => {
    const interceptor = authTokenDPoPInterceptor({
      tokenProvider: async () => 'dpop-token',
    });

    const headers = await captureHeaders(interceptor);

    expect(headers.get('Authorization')).to.equal('Bearer dpop-token');
    expect(headers.get('DPoP')).to.be.a('string');
    expect(headers.get('DPoP')!.split('.')).to.have.length(3); // JWT format
    expect(headers.get('X-VirtruPubKey')).to.be.a('string');
    expect(headers.get('X-VirtruPubKey')!.length).to.be.greaterThan(0);
  });

  it('exposes dpopKeys as a promise that resolves to a KeyPair', async () => {
    const interceptor = authTokenDPoPInterceptor({
      tokenProvider: async () => 'token',
    });

    expect(interceptor.dpopKeys).to.be.instanceOf(Promise);
    const keys = await interceptor.dpopKeys;
    expect(keys).to.have.property('publicKey');
    expect(keys).to.have.property('privateKey');
  });

  it('uses provided dpopKeys instead of generating new ones', async () => {
    // Import crypto service to generate known keys
    const cryptoService = await import('../../tdf3/src/crypto/index.js');
    const knownKeys = await cryptoService.generateSigningKeyPair();

    const interceptor = authTokenDPoPInterceptor({
      tokenProvider: async () => 'token',
      dpopKeys: knownKeys,
    });

    const resolvedKeys = await interceptor.dpopKeys;
    expect(resolvedKeys).to.equal(knownKeys);
  });

  it('generates a valid DPoP proof JWT', async () => {
    const interceptor = authTokenDPoPInterceptor({
      tokenProvider: async () => 'test-access-token',
    });

    const headers = await captureHeaders(interceptor, 'https://example.com/v1/rewrap');
    const dpopToken = headers.get('DPoP')!;

    // Decode the JWT payload (middle part)
    const base64UrlDecode = (input: string): string => {
      let b64 = input.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) {
        b64 += '=';
      }
      return atob(b64);
    };
    const [headerB64, payloadB64] = dpopToken.split('.');
    const header = JSON.parse(base64UrlDecode(headerB64));
    const payload = JSON.parse(base64UrlDecode(payloadB64));

    expect(header.typ).to.equal('dpop+jwt');
    expect(header.jwk).to.be.an('object');
    expect(payload.htm).to.equal('POST');
    expect(payload.htu).to.equal('https://example.com/v1/rewrap');
    expect(payload.iat).to.be.a('number');
    expect(payload.jti).to.be.a('string');
  });
});

// --- authProviderInterceptor ---

describe('authProviderInterceptor', () => {
  it('delegates to authProvider.withCreds and applies returned headers', async () => {
    const mockAuthProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (req: HttpRequest) =>
        withHeaders(req, {
          Authorization: 'Bearer provider-token',
          'X-Custom': 'custom-value',
        }),
    };

    const interceptor = authProviderInterceptor(mockAuthProvider);
    const headers = await captureHeaders(interceptor);

    expect(headers.get('Authorization')).to.equal('Bearer provider-token');
    expect(headers.get('X-Custom')).to.equal('custom-value');
  });

  it('wraps updateClientPublicKey errors with helpful message', async () => {
    const failingProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async () => {
        throw new Error('public key not configured');
      },
    };

    const interceptor = authProviderInterceptor(failingProvider);
    try {
      await captureHeaders(interceptor);
      expect.fail('should have thrown');
    } catch (e) {
      expect((e as Error).message).to.include('DPoP key binding is not complete');
    }
  });
});

// --- resolveInterceptors / resolveAuthConfig / isInterceptorConfig ---

describe('AuthConfig utilities', () => {
  const stubAuthProvider: AuthProvider = {
    updateClientPublicKey: async () => {},
    withCreds: async (req) => req,
  };

  describe('isInterceptorConfig', () => {
    it('returns true for interceptor config', () => {
      const noop: Interceptor = (next) => (req) => next(req);
      expect(isInterceptorConfig({ interceptors: [noop] })).to.equal(true);
    });

    it('returns false for AuthProvider', () => {
      expect(isInterceptorConfig(stubAuthProvider)).to.equal(false);
    });
  });

  describe('resolveInterceptors', () => {
    it('returns interceptors directly from interceptor config', () => {
      const noop: Interceptor = (next) => (req) => next(req);
      const result = resolveInterceptors({ interceptors: [noop] });
      expect(result).to.deep.equal([noop]);
    });

    it('wraps AuthProvider into an interceptor array', () => {
      const result = resolveInterceptors(stubAuthProvider);
      expect(result).to.have.length(1);
      expect(result[0]).to.be.a('function');
    });
  });

  describe('resolveAuthConfig', () => {
    it('preserves authProvider in the result for AuthProvider input', () => {
      const result = resolveAuthConfig(stubAuthProvider);
      expect(result.authProvider).to.equal(stubAuthProvider);
      expect(result.interceptors).to.have.length(1);
    });

    it('returns undefined authProvider for interceptor config', () => {
      const noop: Interceptor = (next) => (req) => next(req);
      const result = resolveAuthConfig({ interceptors: [noop] });
      expect(result.authProvider).to.equal(undefined);
      expect(result.interceptors).to.deep.equal([noop]);
    });
  });
});
