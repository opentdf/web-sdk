import { expect } from '@esm-bundle/chai';
import sinon from 'sinon';

// --- Adjust the import paths to match your project structure ---
import {
  fetchWrappedKey,
  fetchKeyAccessServers,
  fetchKasPubKey,
} from '../../../src/access/access-fetch.js';
import {
  ConfigurationError,
  InvalidFileError,
  NetworkError,
  PermissionDeniedError,
  ServiceError,
  UnauthenticatedError,
} from '../../../src/errors.js';
import { OriginAllowList } from '../../../src/access.js';
import type { AuthProvider } from '../../../src/index.js';
// -------------------------------------------------------------

describe('access-fetch.js', () => {
  let fetchStub: sinon.SinonStub;

  // A mock authProvider for testing purposes
  const mockAuthProvider: AuthProvider = {
    withCreds: sinon.stub().callsFake(async (req) => ({
      ...req,
      headers: { ...req.headers, Authorization: 'Bearer test-token' },
    })),
  } as unknown as AuthProvider;

  // Helper to create mock fetch responses
  // @ts-expect-error Not caring about any in tests.
  const createMockResponse = (body, ok = true, status = 200, statusText = 'OK') => {
    return Promise.resolve({
      ok,
      status,
      statusText,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
    } as Response);
  };

  beforeEach(() => {
    // Stub window.fetch before each test
    fetchStub = sinon.stub(window, 'fetch');
    // Reset any previous stub behavior
    // @ts-expect-error Stub
    mockAuthProvider.withCreds.resetHistory();
  });

  afterEach(() => {
    // Restore all stubs
    sinon.restore();
  });

  describe('fetchWrappedKey', () => {
    const url = 'https://kas.example.com/rewrap';
    const requestBody = { signedRequestToken: 'test-token' };

    it('should return a rewrapped key on a successful request', async () => {
      const mockResponseData = {
        metadata: { a: 1 },
        entityWrappedKey: 'ewk-abc',
        sessionPublicKey: 'spk-xyz',
        schemaVersion: '1.0.0',
      };
      fetchStub.returns(createMockResponse(mockResponseData));

      const result = await fetchWrappedKey(url, requestBody, mockAuthProvider);

      expect(result).to.deep.equal(mockResponseData);
      // @ts-expect-error Stub is not typed.
      expect(mockAuthProvider.withCreds.calledOnce).to.be.true;
      expect(fetchStub.calledOnce).to.be.true;
      const fetchCall = fetchStub.getCall(0);
      expect(fetchCall.args[0]).to.equal(url);
      expect(JSON.parse(fetchCall.args[1].body as string)).to.deep.equal(requestBody);
    });

    it('should throw NetworkError if the fetch call fails', async () => {
      const fetchError = new Error('Network failure');
      fetchStub.rejects(fetchError);

      try {
        await fetchWrappedKey(url, requestBody, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(NetworkError);
        expect(e.message).to.equal(`unable to fetch wrapped key from [${url}]`);
      }
    });

    it('should throw InvalidFileError for a 400 Bad Request response', async () => {
      const errorText = 'Invalid token format';
      fetchStub.returns(createMockResponse(errorText, false, 400, 'Bad Request'));

      try {
        await fetchWrappedKey(url, requestBody, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(InvalidFileError);
        expect(e.message).to.equal(`400 for [${url}]: rewrap bad request [${errorText}]`);
      }
    });

    it('should throw UnauthenticatedError for a 401 Unauthorized response', async () => {
      fetchStub.returns(createMockResponse('Auth failed', false, 401, 'Unauthorized'));

      try {
        await fetchWrappedKey(url, requestBody, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(UnauthenticatedError);
        expect(e.message).to.equal(`401 for [${url}]; rewrap auth failure`);
      }
    });

    it('should throw PermissionDeniedError for a 403 Forbidden response', async () => {
      fetchStub.returns(createMockResponse('Forbidden', false, 403, 'Forbidden'));

      try {
        await fetchWrappedKey(url, requestBody, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(PermissionDeniedError);
        expect(e.message).to.equal(`403 for [${url}]; rewrap permission denied`);
      }
    });

    it('should throw ServiceError for a 5xx server error response', async () => {
      const errorText = 'Internal Server Error';
      fetchStub.returns(createMockResponse(errorText, false, 500, 'Internal Server Error'));

      try {
        await fetchWrappedKey(url, requestBody, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(ServiceError);
        expect(e.message).to.equal(
          `500 for [${url}]: rewrap failure due to service error [${errorText}]`
        );
      }
    });

    it('should throw NetworkError for other non-ok responses', async () => {
      fetchStub.returns(createMockResponse('Not Found', false, 404, 'Not Found'));

      try {
        await fetchWrappedKey(url, requestBody, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(NetworkError);
        expect(e.message).to.equal(`POST ${url} => 404 Not Found`);
      }
    });
  });

  describe('fetchKeyAccessServers', () => {
    const platformUrl = 'https://platform.example.com';

    it('should fetch a list of servers with a single page', async () => {
      const mockResponse = {
        keyAccessServers: [{ uri: 'https://kas1.example.com' }],
        pagination: { nextOffset: 0 },
      };
      fetchStub.returns(createMockResponse(mockResponse));

      const result = await fetchKeyAccessServers(platformUrl, mockAuthProvider);

      expect(result).to.be.instanceOf(OriginAllowList);
      expect(result.origins).to.have.members([
        'https://platform.example.com',
        'https://kas1.example.com',
      ]);
      expect(fetchStub.calledOnce).to.be.true;
    });

    it('should handle pagination and combine results from multiple pages', async () => {
      const page1Response = {
        keyAccessServers: [{ uri: 'https://kas1.example.com' }],
        pagination: { nextOffset: 1 },
      };
      const page2Response = {
        keyAccessServers: [{ uri: 'https://kas2.example.com' }],
        pagination: { nextOffset: 0 },
      };

      fetchStub.onCall(0).returns(createMockResponse(page1Response));
      fetchStub.onCall(1).returns(createMockResponse(page2Response));

      const result = await fetchKeyAccessServers(platformUrl, mockAuthProvider);

      expect(result).to.be.instanceOf(OriginAllowList);
      expect(result.origins).to.have.members([
        'https://kas1.example.com',
        'https://kas2.example.com',
        'https://platform.example.com',
      ]);
      expect(fetchStub.calledTwice).to.be.true;
      expect(fetchStub.getCall(0).args[0]).to.include('offset=0');
      expect(fetchStub.getCall(1).args[0]).to.include('offset=1');
    });

    it('should throw a NetworkError if the fetch call fails', async () => {
      const fetchError = new Error('Network failure');
      fetchStub.rejects(fetchError);

      try {
        await fetchKeyAccessServers(platformUrl, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(NetworkError);
        expect(e.message).to.include('unable to fetch kas list');
      }
    });

    it('should throw a ServiceError for a non-ok HTTP response', async () => {
      fetchStub.returns(createMockResponse('Service Unavailable', false, 503));

      try {
        await fetchKeyAccessServers(platformUrl, mockAuthProvider);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(ServiceError);
        expect(e.message).to.include('unable to fetch kas list');
        expect(e.message).to.include('status: 503');
      }
    });
  });

  describe('fetchKasPubKey', () => {
    const kasEndpoint = 'https://kas.example.com';
    // FIX: Provide a real, valid base64-encoded key. The `...` is not valid.
    const mockPemKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2p7wtvu1GQY5f4YdPiTa
qabW7JVRX8y548pme3m4R25hdAbTXsNuqAAy9DaqWT+iUJ5BE2oSvHZwwUfRAMTN
D3VxNnBRxLkj2FL+tnVAMZ+qyJ++2cpJhotuXlROcCIZXltjrqYcfaUMBnqrGlI9
CHoIvVqOLHWNxsEr1QzgBjUH2Yrispnb3r11yB8jdfAtxewtX9pPXP10mNeVr9/C
EAnqlA1Io0Qv3SZZ3h0VWtCMwQkrF76p5c8onD/pgRCO3Udx6K+RLbSkEJell5kj
1EuR3P3E1anNU/NoWdh23c5GXtQvXz4yKy+05kUTZ5xmh/H/0T8WqOrjcnOZycBn
ywIDAQAB
-----END PUBLIC KEY-----`;

    it('should fetch and return KAS public key info on success', async () => {
      const mockResponse = { publicKey: mockPemKey, kid: 'test-kid' };
      fetchStub.returns(createMockResponse(mockResponse));

      const result = await fetchKasPubKey(kasEndpoint);

      expect(result).to.deep.equal({
        publicKey: mockPemKey,
        url: kasEndpoint,
        algorithm: 'rsa:2048',
        kid: 'test-kid',
      });

      // IMPROVEMENT: Test URL components instead of a hardcoded string.
      const fetchedUrl = new URL(fetchStub.firstCall.args[0]);
      expect(fetchedUrl.origin).to.equal(kasEndpoint);
      expect(fetchedUrl.pathname).to.equal('/v2/kas_public_key');
      expect(fetchedUrl.searchParams.get('algorithm')).to.equal('rsa:2048');
      expect(fetchedUrl.searchParams.get('v')).to.equal('2');
    });

    it('should throw ConfigurationError if kasEndpoint is missing', async () => {
      try {
        await fetchKasPubKey('');
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(ConfigurationError);
        expect(e.message).to.equal('KAS definition not found');
      }
    });

    it('should throw ConfigurationError for an invalid kasEndpoint URL', async () => {
      const invalidUrl = 'not-a-url';
      // validateSecureUrlStub.throws(new ConfigurationError(`KAS definition invalid: [${invalidUrl}]`));
      try {
        await fetchKasPubKey(invalidUrl);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(ConfigurationError);
        expect(e.message).to.equal(`KAS definition invalid: [${invalidUrl}]`);
      }
    });

    it('should throw NetworkError if fetch fails', async () => {
      const fetchError = new Error('Network failure');
      fetchStub.rejects(fetchError);

      try {
        await fetchKasPubKey(kasEndpoint);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(NetworkError);
        expect(e.message).to.include('unable to fetch public key');
      }
    });

    it('should throw ConfigurationError for a 404 response', async () => {
      fetchStub.returns(createMockResponse('Not Found', false, 404));

      try {
        await fetchKasPubKey(kasEndpoint);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(ConfigurationError);
        // IMPROVEMENT: Make error message assertion less brittle
        expect(e.message).to.include('404 for');
        expect(e.message).to.include('kas.example.com/v2/kas_public_key');
      }
    });

    it('should throw UnauthenticatedError for a 401 response', async () => {
      fetchStub.returns(createMockResponse('Unauthorized', false, 401));

      try {
        await fetchKasPubKey(kasEndpoint);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(UnauthenticatedError);
        // IMPROVEMENT: Make error message assertion less brittle
        expect(e.message).to.include('401 for');
        expect(e.message).to.include('kas.example.com/v2/kas_public_key');
      }
    });

    it('should throw PermissionDeniedError for a 403 response', async () => {
      fetchStub.returns(createMockResponse('Forbidden', false, 403));

      try {
        await fetchKasPubKey(kasEndpoint);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(PermissionDeniedError);
        // IMPROVEMENT: Make error message assertion less brittle
        expect(e.message).to.include('403 for');
        expect(e.message).to.include('kas.example.com/v2/kas_public_key');
      }
    });

    it('should throw NetworkError if response JSON is missing publicKey', async () => {
      const invalidResponse = { kid: 'only-a-kid' };
      fetchStub.returns(createMockResponse(invalidResponse));

      try {
        await fetchKasPubKey(kasEndpoint);
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).to.be.instanceOf(NetworkError);
        expect(e.message).to.equal(
          `invalid response from public key endpoint [${JSON.stringify(invalidResponse)}]`
        );
      }
    });
  });
});
