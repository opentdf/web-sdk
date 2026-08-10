import { expect } from 'chai';
import sinon from 'sinon';
import { fetchKasPubKey, fetchKeyAccessServers, fetchWrappedKey } from '../../../src/access.js';
import {
  InvalidFileError,
  NetworkError,
  PermissionDeniedError,
  ServiceError,
  UnauthenticatedError,
} from '../../../src/errors.js';
import type { AuthProvider, HttpRequest } from '../../../src/index.js';

const kasUrl = 'http://localhost:3000/kas';
const restRewrapUrl = `${kasUrl}/v2/rewrap`;

const authProvider: AuthProvider = {
  updateClientPublicKey: () => Promise.resolve(),
  withCreds: (req: HttpRequest) => Promise.resolve(req),
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

// A Connect-protocol unary error response.
const connectError = (code: string, status: number) =>
  json({ code, message: `${code} from test` }, status);

const notFound = () => new Response('404 page not found', { status: 404 });

type Route = (url: string) => Response | undefined;

describe('access RPC/REST fallback', () => {
  let fetchStub: sinon.SinonStub;

  const isRpc = (url: string) => /\/[a-z.]+\.[A-Za-z]+Service\//.test(url);

  /** Stubs fetch; rpc handles Connect calls, rest handles everything else. */
  function serve(rpc: Route, rest: Route) {
    fetchStub.callsFake((input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const res = (isRpc(url) ? rpc : rest)(url);
      return Promise.resolve(res ?? notFound());
    });
  }

  const restCalls = () =>
    fetchStub.getCalls().filter((c) => {
      const a = c.args[0] as RequestInfo | URL;
      return !isRpc(a instanceof Request ? a.url : String(a));
    }).length;

  beforeEach(() => {
    fetchStub = sinon.stub(globalThis, 'fetch');
    sinon.stub(console, 'info');
    sinon.stub(console, 'log');
  });

  afterEach(() => {
    sinon.restore();
  });

  const rewrap = () => fetchWrappedKey(restRewrapUrl, 'token', authProvider, []);

  async function expectReject(p: Promise<unknown>): Promise<unknown> {
    try {
      await p;
    } catch (e) {
      return e;
    }
    expect.fail('expected rejection');
  }

  describe('fetchWrappedKey', () => {
    it('short-circuits on a definitive RPC error (Connect-only platform)', async () => {
      for (const [code, status, type] of [
        ['unauthenticated', 401, UnauthenticatedError],
        ['permission_denied', 403, PermissionDeniedError],
        ['invalid_argument', 400, InvalidFileError],
      ] as const) {
        fetchStub.resetHistory();
        serve(() => connectError(code, status), notFound);
        const e = await expectReject(rewrap());
        expect(e).to.be.instanceOf(type);
        expect(restCalls(), code).to.equal(0);
      }
    });

    it('falls back to REST when the RPC endpoint is missing (REST-only platform)', async () => {
      const restResponse = { entityWrappedKey: 'abc', sessionPublicKey: 'pem' };
      serve(notFound, (url) => (url === restRewrapUrl ? json(restResponse) : undefined));
      const result = await rewrap();
      expect(result).to.deep.equal(restResponse);
      expect(restCalls()).to.equal(1);
    });

    it('surfaces a definitive REST error over the RPC "endpoint missing" error', async () => {
      for (const [status, type] of [
        [401, UnauthenticatedError],
        [403, PermissionDeniedError],
        [400, InvalidFileError],
      ] as const) {
        serve(notFound, () => new Response('nope', { status }));
        const e = await expectReject(rewrap());
        expect(e, String(status)).to.be.instanceOf(type);
      }
    });

    it('surfaces the RPC error when REST fails non-definitively', async () => {
      serve(
        () => connectError('unavailable', 503),
        () => notFound()
      );
      const e = await expectReject(rewrap());
      expect(e).to.be.instanceOf(ServiceError);
      expect((e as Error).message).to.not.include('404');
    });
  });

  describe('fetchKasPubKey', () => {
    it('falls back to REST when base key and RPC are unavailable', async () => {
      serve(notFound, (url) =>
        url.includes('/v2/kas_public_key') ? json({ publicKey: 'PEM', kid: 'k1' }) : undefined
      );
      const result = await fetchKasPubKey(kasUrl);
      expect(result.publicKey).to.equal('PEM');
      expect(result.kid).to.equal('k1');
    });

    it('surfaces a definitive REST error over the RPC NetworkError', async () => {
      serve(notFound, () => new Response('nope', { status: 403 }));
      const e = await expectReject(fetchKasPubKey(kasUrl));
      expect(e).to.be.instanceOf(PermissionDeniedError);
    });

    it('surfaces the RPC error when REST 404s (Connect-only platform)', async () => {
      serve(
        () => connectError('unavailable', 503),
        () => notFound()
      );
      const e = await expectReject(fetchKasPubKey(kasUrl));
      expect(e).to.be.instanceOf(NetworkError);
      expect((e as Error).message).to.include('[PublicKey]');
    });
  });

  describe('fetchKeyAccessServers', () => {
    it('falls back to REST when the RPC endpoint is missing', async () => {
      serve(notFound, (url) =>
        url.includes('/key-access-servers')
          ? json({ keyAccessServers: [{ uri: 'https://kas.example.com' }] })
          : undefined
      );
      const list = await fetchKeyAccessServers('http://localhost:3000', authProvider);
      expect(list.allows('https://kas.example.com/kas')).to.equal(true);
    });

    it('surfaces the RPC error when both fail', async () => {
      serve(notFound, notFound);
      const e = await expectReject(fetchKeyAccessServers('http://localhost:3000', authProvider));
      expect(e).to.be.instanceOf(NetworkError);
      expect((e as Error).message).to.include('[ListKeyAccessServers]');
    });
  });
});
