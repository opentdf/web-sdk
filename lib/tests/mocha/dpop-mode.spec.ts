import { expect } from 'chai';

import {
  DPoPModeResolver,
  advertisesRFC9449,
  fullDPoPHTU,
  legacyRpcDPoPHTU,
} from '../../src/auth/dpop-mode.js';
import { authProviderInterceptor } from '../../src/auth/interceptors.js';
import type { AuthProvider, HttpRequest } from '../../src/auth/auth.js';

const rpcUrl = 'https://kas.example/proxy/kas.AccessService/Rewrap?ignored=1#fragment';
const procedure = '/kas.AccessService/Rewrap';
const fullHtu = 'https://kas.example/proxy/kas.AccessService/Rewrap';

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function requestHref(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

describe('resource DPoP mode discovery', () => {
  it('uses the bare procedure on legacy servers and strips proxy prefixes', async () => {
    const requests: Array<{ url: string; init: RequestInit | undefined }> = [];
    const resolver = new DPoPModeResolver({
      fetch: (input, init) => {
        requests.push({ url: requestHref(input), init });
        if (requestHref(input).includes('GetWellKnownConfiguration')) {
          return Promise.resolve(
            jsonResponse({ configuration: { platform_issuer: 'https://idp.example' } })
          );
        }
        return Promise.resolve(jsonResponse({}, 404));
      },
    });

    expect(await resolver.htuForRpc(rpcUrl)).to.equal(procedure);
    expect(await resolver.htuForRpc(rpcUrl)).to.equal(procedure);
    expect(requests).to.have.length(2);
    expect(requests[0].url).to.equal(
      'https://kas.example/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration'
    );
    expect(requests[0].init?.method).to.equal('POST');
    expect(requests[0].init?.body).to.equal('{}');
    expect(requests[1].url).to.equal('https://kas.example/.well-known/oauth-protected-resource');
    expect(requests[1].init?.method).to.equal('GET');
    for (const request of requests) {
      expect(request.init?.credentials).to.equal('omit');
      expect(request.init?.redirect).to.equal('manual');
      const headers = new Headers(request.init?.headers);
      expect(headers.has('Authorization')).to.equal(false);
      expect(headers.has('DPoP')).to.equal(false);
    }
  });

  it('uses full URLs when either advertisement is present', async () => {
    const fromPlatform = new DPoPModeResolver({
      fetch: () => Promise.resolve(jsonResponse({ configuration: { dpop: { rfc9449: true } } })),
    });
    expect(await fromPlatform.htuForRpc(rpcUrl)).to.equal(fullHtu);

    const fromMetadata = new DPoPModeResolver({
      fetch: (input) =>
        Promise.resolve(
          requestHref(input).includes('GetWellKnownConfiguration')
            ? jsonResponse({ configuration: { dpop: { rfc9449: false } } })
            : jsonResponse({ dpop_signing_alg_values_supported: ['ES256'] })
        ),
    });
    expect(await fromMetadata.htuForRpc(rpcUrl)).to.equal(fullHtu);
    expect(
      advertisesRFC9449({
        dpop: { rfc9449: false },
        dpop_signing_alg_values_supported: ['ES256'],
      })
    ).to.equal(false);
  });

  it('caches per origin, shares simultaneous discovery, and retries inconclusive failures', async () => {
    let now = 0;
    let calls = 0;
    let failing = true;
    const resolver = new DPoPModeResolver({
      now: () => now,
      fetch: (input) => {
        calls++;
        if (failing) return Promise.reject(new Error('network unavailable'));
        if (requestHref(input).includes('GetWellKnownConfiguration')) {
          return Promise.resolve(
            jsonResponse({ configuration: { dpop_signing_alg_values_supported: ['ES256'] } })
          );
        }
        return Promise.resolve(jsonResponse({}, 404));
      },
    });

    expect(
      await Promise.all([resolver.htuForRpc(rpcUrl), resolver.htuForRpc(rpcUrl)])
    ).to.deep.equal([procedure, procedure]);
    expect(calls).to.equal(2);
    failing = false;
    now = 29_999;
    expect(await resolver.htuForRpc(rpcUrl)).to.equal(procedure);
    now = 30_000;
    expect(await resolver.htuForRpc(rpcUrl)).to.equal(fullHtu);
    expect(calls).to.equal(3);
    expect(await resolver.htuForRpc('https://other.example/kas.AccessService/Rewrap')).to.equal(
      'https://other.example/kas.AccessService/Rewrap'
    );
    expect(calls).to.equal(4);
  });

  it('supports fixed modes and RFC 9449 URI normalization without discovery', async () => {
    const fetcher: typeof fetch = () => Promise.reject(new Error('fixed mode must not discover'));
    expect(
      await new DPoPModeResolver({ mode: 'legacy', fetch: fetcher }).htuForRpc(rpcUrl)
    ).to.equal(procedure);
    expect(
      await new DPoPModeResolver({ mode: 'rfc9449', fetch: fetcher }).htuForRpc(rpcUrl)
    ).to.equal(fullHtu);
    expect(fullDPoPHTU(rpcUrl)).to.equal(fullHtu);
    expect(legacyRpcDPoPHTU(rpcUrl)).to.equal(procedure);
  });

  it('passes the actual Connect URL and negotiated htu to an AuthProvider', async () => {
    let seen: HttpRequest | undefined;
    const provider: AuthProvider = {
      dpopModeResolver: new DPoPModeResolver({ mode: 'legacy' }),
      updateClientPublicKey: () => Promise.resolve(),
      withCreds: (request) => {
        seen = request;
        return Promise.resolve(request);
      },
    };
    const interceptor = authProviderInterceptor(provider);
    const request = { url: rpcUrl, header: new Headers() } as Parameters<
      ReturnType<typeof interceptor>
    >[0];
    const next = (r: typeof request) => Promise.resolve(r);
    await interceptor(next as unknown as Parameters<typeof interceptor>[0])(request);
    expect(seen?.url).to.equal(rpcUrl);
    expect(seen?.dpopHtu).to.equal(procedure);
  });
});
