import { expect } from 'chai';
import {
  type AlgorithmUrn,
  type AsymmetricSigningAlgorithm,
  type Binary,
  type CryptoService,
  type DecryptResult,
  type ECCurve,
  type EncryptResult,
  type HashAlgorithm,
  type HkdfParams,
  type PemKeyPair,
  type PublicKeyInfo,
} from '../../../tdf3/index.js';
import { Client } from '../../../tdf3/src/client/index.js';
import { OpenTDF } from '../../../src/opentdf.js';
import { type AuthProvider, type HttpRequest } from '../../../src/auth/providers.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';

// not implemented error
const NOT_IMPLEMENTED = 'Function not implemented.';

describe('CryptoService DI', () => {
  it('Loads mock CryptoService', async () => {
    const cryptoService: CryptoService = {
      name: 'mock',
      method: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      decrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined,
        authTag?: Binary | undefined
      ): Promise<DecryptResult> {
        throw new Error(NOT_IMPLEMENTED);
      },
      decryptWithPrivateKey: function (
        encryptedPayload: Binary,
        privateKey: string
      ): Promise<Binary> {
        throw new Error(NOT_IMPLEMENTED);
      },
      encrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined
      ): Promise<EncryptResult> {
        throw new Error(NOT_IMPLEMENTED);
      },
      encryptWithPublicKey: function (payload: Binary, publicKey: string): Promise<Binary> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateInitializationVector: function (length?: number): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateKey: function (length?: number): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateKeyPair: function (size?: number | undefined): Promise<PemKeyPair> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateSigningKeyPair: function (): Promise<PemKeyPair> {
        throw new Error(NOT_IMPLEMENTED);
      },
      hmac: function (key: string, content: string): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      randomBytes: function (byteLength: number): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      sha256: function (content: string): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      sign: function (
        data: Uint8Array,
        privateKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      verify: function (
        data: Uint8Array,
        signature: Uint8Array,
        publicKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<boolean> {
        throw new Error(NOT_IMPLEMENTED);
      },
      signSymmetric: function (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      verifySymmetric: function (
        data: Uint8Array,
        signature: Uint8Array,
        key: Uint8Array
      ): Promise<boolean> {
        throw new Error(NOT_IMPLEMENTED);
      },
      digest: function (algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      extractPublicKeyPem: function (certOrPem: string): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateECKeyPair: function (curve?: ECCurve): Promise<PemKeyPair> {
        throw new Error(NOT_IMPLEMENTED);
      },
      deriveKeyFromECDH: function (
        privateKeyPem: string,
        publicKeyPem: string,
        hkdfParams: HkdfParams
      ): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      importPublicKeyPem: function (pem: string): Promise<PublicKeyInfo> {
        throw new Error(NOT_IMPLEMENTED);
      },
      jwkToPem: function (jwk: JsonWebKey): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
    };
    const c = new Client({
      cryptoService,
      clientId: 'oidc-client',
      dpopEnabled: false,
      kasEndpoint: 'https://localhost/',
    });
    try {
      await c.encrypt({
        source: new ReadableStream({
          pull(controller) {
            controller.enqueue(new TextEncoder().encode('hello world'));
            controller.close();
          },
        }),
      });
    } catch (e) {
      expect(() => {
        throw e;
      }).to.throw(NOT_IMPLEMENTED);
    }
  });

  it('OpenTDF accepts custom CryptoService', async () => {
    const mockCryptoService: CryptoService = {
      name: 'CustomCryptoService',
      method: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      decrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined,
        authTag?: Binary | undefined
      ): Promise<DecryptResult> {
        throw new Error(NOT_IMPLEMENTED);
      },
      decryptWithPrivateKey: function (
        encryptedPayload: Binary,
        privateKey: string
      ): Promise<Binary> {
        throw new Error(NOT_IMPLEMENTED);
      },
      encrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined
      ): Promise<EncryptResult> {
        throw new Error(NOT_IMPLEMENTED);
      },
      encryptWithPublicKey: function (payload: Binary, publicKey: string): Promise<Binary> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateInitializationVector: function (length?: number): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateKey: function (length?: number): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateKeyPair: function (size?: number | undefined): Promise<PemKeyPair> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateSigningKeyPair: function (): Promise<PemKeyPair> {
        throw new Error(NOT_IMPLEMENTED);
      },
      hmac: function (key: string, content: string): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      randomBytes: function (byteLength: number): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      sha256: function (content: string): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      sign: function (
        data: Uint8Array,
        privateKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      verify: function (
        data: Uint8Array,
        signature: Uint8Array,
        publicKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<boolean> {
        throw new Error(NOT_IMPLEMENTED);
      },
      signSymmetric: function (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      verifySymmetric: function (
        data: Uint8Array,
        signature: Uint8Array,
        key: Uint8Array
      ): Promise<boolean> {
        throw new Error(NOT_IMPLEMENTED);
      },
      digest: function (algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      extractPublicKeyPem: function (certOrPem: string): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
      generateECKeyPair: function (curve?: ECCurve): Promise<PemKeyPair> {
        throw new Error(NOT_IMPLEMENTED);
      },
      deriveKeyFromECDH: function (
        privateKeyPem: string,
        publicKeyPem: string,
        hkdfParams: HkdfParams
      ): Promise<Uint8Array> {
        throw new Error(NOT_IMPLEMENTED);
      },
      importPublicKeyPem: function (pem: string): Promise<PublicKeyInfo> {
        throw new Error(NOT_IMPLEMENTED);
      },
      jwkToPem: function (jwk: JsonWebKey): Promise<string> {
        throw new Error(NOT_IMPLEMENTED);
      },
    };

    const mockAuthProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => httpReq,
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
      withCreds: async (httpReq: HttpRequest) => httpReq,
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
    const mockCryptoService: CryptoService = {
      name: 'CustomCryptoService',
      method: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      decrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined,
        authTag?: Binary | undefined
      ): Promise<DecryptResult> {
        throw new Error('Function not implemented.');
      },
      decryptWithPrivateKey: function (
        encryptedPayload: Binary,
        privateKey: string
      ): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      encrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined
      ): Promise<EncryptResult> {
        throw new Error('Function not implemented.');
      },
      encryptWithPublicKey: function (payload: Binary, publicKey: string): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      generateInitializationVector: function (length?: number): Promise<string> {
        throw new Error('Function not implemented.');
      },
      generateKey: function (length?: number): Promise<string> {
        throw new Error('Function not implemented.');
      },
      generateKeyPair: function (size?: number | undefined): Promise<PemKeyPair> {
        throw new Error('Function not implemented.');
      },
      generateSigningKeyPair: function (): Promise<PemKeyPair> {
        throw new Error('Function not implemented.');
      },
      hmac: function (key: string, content: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      randomBytes: function (byteLength: number): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      sha256: function (content: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      sign: function (
        data: Uint8Array,
        privateKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verify: function (
        data: Uint8Array,
        signature: Uint8Array,
        publicKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      signSymmetric: function (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verifySymmetric: function (
        data: Uint8Array,
        signature: Uint8Array,
        key: Uint8Array
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      digest: function (algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      extractPublicKeyPem: function (certOrPem: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      generateECKeyPair: function (curve?: ECCurve): Promise<PemKeyPair> {
        throw new Error('Function not implemented.');
      },
      deriveKeyFromECDH: function (
        privateKeyPem: string,
        publicKeyPem: string,
        hkdfParams: HkdfParams
      ): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      importPublicKeyPem: function (pem: string): Promise<PublicKeyInfo> {
        throw new Error('Function not implemented.');
      },
      jwkToPem: function (jwk: JsonWebKey): Promise<string> {
        throw new Error('Function not implemented.');
      },
    };

    const mockAuthProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => httpReq,
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
      withCreds: async (httpReq: HttpRequest) => httpReq,
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
    const mockCryptoService: CryptoService = {
      name: 'CustomCryptoService',
      method: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      decrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined,
        authTag?: Binary | undefined
      ): Promise<DecryptResult> {
        throw new Error('Function not implemented.');
      },
      decryptWithPrivateKey: function (
        encryptedPayload: Binary,
        privateKey: string
      ): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      encrypt: function (
        payload: Binary,
        key: Binary,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined
      ): Promise<EncryptResult> {
        throw new Error('Function not implemented.');
      },
      encryptWithPublicKey: function (payload: Binary, publicKey: string): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      generateInitializationVector: function (length?: number): Promise<string> {
        throw new Error('Function not implemented.');
      },
      generateKey: function (length?: number): Promise<string> {
        throw new Error('Function not implemented.');
      },
      generateKeyPair: function (size?: number | undefined): Promise<PemKeyPair> {
        throw new Error('Function not implemented.');
      },
      generateSigningKeyPair: function (): Promise<PemKeyPair> {
        throw new Error('Function not implemented.');
      },
      hmac: function (key: string, content: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      randomBytes: function (byteLength: number): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      sha256: function (content: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      sign: function (
        data: Uint8Array,
        privateKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verify: function (
        data: Uint8Array,
        signature: Uint8Array,
        publicKeyPem: string,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      signSymmetric: function (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verifySymmetric: function (
        data: Uint8Array,
        signature: Uint8Array,
        key: Uint8Array
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      digest: function (algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      extractPublicKeyPem: function (certOrPem: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      generateECKeyPair: function (curve?: ECCurve): Promise<PemKeyPair> {
        throw new Error('Function not implemented.');
      },
      deriveKeyFromECDH: function (
        privateKeyPem: string,
        publicKeyPem: string,
        hkdfParams: HkdfParams
      ): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      importPublicKeyPem: function (pem: string): Promise<PublicKeyInfo> {
        throw new Error('Function not implemented.');
      },
      jwkToPem: function (jwk: JsonWebKey): Promise<string> {
        throw new Error('Function not implemented.');
      },
    };

    const mockAuthProvider: AuthProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: HttpRequest) => httpReq,
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
      withCreds: async (httpReq: HttpRequest) => httpReq,
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
});
