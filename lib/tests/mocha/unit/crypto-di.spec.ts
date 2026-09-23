import { expect } from 'chai';
import type { CryptoService } from '../../../tdf3/index.js';
import { OpenTDF } from '../../../src/opentdf.js';
import { type AuthProvider, type HttpRequest } from '../../../src/auth/providers.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';

const NOT_IMPLEMENTED = 'Function not implemented.';

const notImplemented = (): never => {
  throw new Error(NOT_IMPLEMENTED);
};

function createMockCryptoService(): CryptoService {
  return new Proxy(
    {
      name: 'CustomCryptoService',
      method: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    },
    {
      get(target, property) {
        if (property === 'name') return target.name;
        if (property === 'method') return target.method;
        return notImplemented;
      },
    }
  ) as CryptoService;
}

describe('CryptoService DI', () => {
  it('Loads mock CryptoService', async () => {
    const mockCryptoService = createMockCryptoService();

    const mockAuthProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
    };

    // Generate dpopKeys using DefaultCryptoService to avoid hanging
    const dpopKeys = await DefaultCryptoService.generateSigningKeyPair();

    const client = new OpenTDF({
      authProvider: mockAuthProvider,
      platformUrl: 'https://platform.example.com',
      cryptoService: mockCryptoService,
      dpopKeys: Promise.resolve(dpopKeys),
    });

    try {
      // Verify the custom crypto service is actually being used
      expect(client.cryptoService.name).to.equal('CustomCryptoService');
      expect(client.cryptoService.method).to.equal('http://www.w3.org/2009/xmlenc11#aes256-gcm');

      // Verify it's also passed through to the TDF3 client
      expect(client.tdf3Client.cryptoService).to.equal(mockCryptoService);
      expect(client.tdf3Client.cryptoService.name).to.equal('CustomCryptoService');
    } finally {
      // Clean up resources
      client.close();
    }
  });

  it('OpenTDF defaults to native crypto when no cryptoService provided', async () => {
    const mockAuthProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
    };

    // Generate dpopKeys using DefaultCryptoService to avoid hanging
    const dpopKeys = await DefaultCryptoService.generateSigningKeyPair();

    const client = new OpenTDF({
      authProvider: mockAuthProvider,
      platformUrl: 'https://platform.example.com',
      dpopKeys: Promise.resolve(dpopKeys),
    });

    try {
      // Verify the default crypto service is being used
      expect(client.cryptoService.name).to.equal('BrowserNativeCryptoService');
      expect(client.cryptoService.method).to.equal('http://www.w3.org/2001/04/xmlenc#aes256-cbc');
    } finally {
      // Clean up resources
      client.close();
    }
  });

  it('OpenTDF accepts custom CryptoService', async () => {
    const mockCryptoService = createMockCryptoService();
    const mockAuthProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: (httpReq: HttpRequest) => Promise.resolve(httpReq),
    };

    // Generate dpopKeys using DefaultCryptoService to avoid hanging
    const dpopKeys = await DefaultCryptoService.generateSigningKeyPair();

    const client = new OpenTDF({
      authProvider: mockAuthProvider,
      platformUrl: 'https://platform.example.com',
      cryptoService: mockCryptoService,
      dpopKeys: Promise.resolve(dpopKeys),
    });

    try {
      // Verify the custom crypto service is actually being used
      expect(client.cryptoService.name).to.equal('CustomCryptoService');
      expect(client.cryptoService.method).to.equal('http://www.w3.org/2009/xmlenc11#aes256-gcm');

      // Verify it's also passed through to the TDF3 client
      expect(client.tdf3Client.cryptoService).to.equal(mockCryptoService);
      expect(client.tdf3Client.cryptoService.name).to.equal('CustomCryptoService');
    } finally {
      // Clean up resources
      client.close();
    }
  });
});
