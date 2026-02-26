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
  type KeyPair,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from '../../../tdf3/index.js';
import { Client } from '../../../tdf3/src/client/index.js';
import { OpenTDF } from '../../../src/opentdf.js';
import { type AuthProvider, type HttpRequest } from '../../../src/auth/providers.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';

describe('CryptoService DI', () => {
  it('Loads mock CryptoService', async () => {
    const cryptoService: CryptoService = {
      name: 'mock',
      method: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      decrypt: function (
        payload: Binary,
        key: SymmetricKey,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined,
        authTag?: Binary | undefined
      ): Promise<DecryptResult> {
        throw new Error('Function not implemented.');
      },
      decryptWithPrivateKey: function (
        encryptedPayload: Binary,
        privateKey: PrivateKey
      ): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      encrypt: function (
        payload: Binary | SymmetricKey,
        key: SymmetricKey,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined
      ): Promise<EncryptResult> {
        throw new Error('Function not implemented.');
      },
      encryptWithPublicKey: function (
        payload: Binary | SymmetricKey,
        publicKey: PublicKey
      ): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      generateKey: function (length?: number): Promise<SymmetricKey> {
        throw new Error('Function not implemented.');
      },
      generateKeyPair: function (size?: number | undefined): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      generateSigningKeyPair: function (): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      hmac: function (key: SymmetricKey, content: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      randomBytes: function (byteLength: number): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      sign: function (
        data: Uint8Array,
        privateKey: PrivateKey,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verify: function (
        data: Uint8Array,
        signature: Uint8Array,
        publicKey: PublicKey,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      signSymmetric: function (data: Uint8Array, key: SymmetricKey): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verifySymmetric: function (
        data: Uint8Array,
        signature: Uint8Array,
        key: SymmetricKey
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      digest: function (algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      generateECKeyPair: function (curve?: ECCurve): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      deriveKeyFromECDH: function (
        privateKey: PrivateKey,
        publicKey: PublicKey,
        hkdfParams: HkdfParams
      ): Promise<SymmetricKey> {
        throw new Error('Function not implemented.');
      },
      importPublicKey: function (pem: string): Promise<PublicKey> {
        throw new Error('Function not implemented.');
      },
      importPrivateKey: function (pem: string): Promise<PrivateKey> {
        throw new Error('Function not implemented.');
      },
      importKeyPair: function (pem: { publicKey: string; privateKey: string }): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      importSymmetricKey: function (keyBytes: Uint8Array): Promise<SymmetricKey> {
        throw new Error('Function not implemented.');
      },
      exportPublicKeyPem: function (key: PublicKey): Promise<string> {
        throw new Error('Function not implemented.');
      },
      exportPublicKeyJwk: function (key: PublicKey): Promise<JsonWebKey> {
        throw new Error('Function not implemented.');
      },
      splitSymmetricKey: function (key: SymmetricKey, numShares: number): Promise<SymmetricKey[]> {
        throw new Error('Function not implemented.');
      },
      mergeSymmetricKeys: function (shares: SymmetricKey[]): Promise<SymmetricKey> {
        throw new Error('Function not implemented.');
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
      }).to.throw('Function not implemented');
    }
  });

  it('OpenTDF accepts custom CryptoService', async () => {
    const mockCryptoService: CryptoService = {
      name: 'CustomCryptoService',
      method: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      decrypt: function (
        payload: Binary,
        key: SymmetricKey,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined,
        authTag?: Binary | undefined
      ): Promise<DecryptResult> {
        throw new Error('Function not implemented.');
      },
      decryptWithPrivateKey: function (
        encryptedPayload: Binary,
        privateKey: PrivateKey
      ): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      encrypt: function (
        payload: Binary | SymmetricKey,
        key: SymmetricKey,
        iv: Binary,
        algorithm?: AlgorithmUrn | undefined
      ): Promise<EncryptResult> {
        throw new Error('Function not implemented.');
      },
      encryptWithPublicKey: function (
        payload: Binary | SymmetricKey,
        publicKey: PublicKey
      ): Promise<Binary> {
        throw new Error('Function not implemented.');
      },
      generateKey: function (length?: number): Promise<SymmetricKey> {
        throw new Error('Function not implemented.');
      },
      generateKeyPair: function (size?: number | undefined): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      generateSigningKeyPair: function (): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      hmac: function (key: SymmetricKey, content: string): Promise<string> {
        throw new Error('Function not implemented.');
      },
      randomBytes: function (byteLength: number): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      sign: function (
        data: Uint8Array,
        privateKey: PrivateKey,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verify: function (
        data: Uint8Array,
        signature: Uint8Array,
        publicKey: PublicKey,
        algorithm: AsymmetricSigningAlgorithm
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      signSymmetric: function (data: Uint8Array, key: SymmetricKey): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      verifySymmetric: function (
        data: Uint8Array,
        signature: Uint8Array,
        key: SymmetricKey
      ): Promise<boolean> {
        throw new Error('Function not implemented.');
      },
      digest: function (algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
        throw new Error('Function not implemented.');
      },
      generateECKeyPair: function (curve?: ECCurve): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      deriveKeyFromECDH: function (
        privateKey: PrivateKey,
        publicKey: PublicKey,
        hkdfParams: HkdfParams
      ): Promise<SymmetricKey> {
        throw new Error('Function not implemented.');
      },
      importPublicKey: function (pem: string): Promise<PublicKey> {
        throw new Error('Function not implemented.');
      },
      importPrivateKey: function (pem: string): Promise<PrivateKey> {
        throw new Error('Function not implemented.');
      },
      importKeyPair: function (pem: { publicKey: string; privateKey: string }): Promise<KeyPair> {
        throw new Error('Function not implemented.');
      },
      importSymmetricKey: function (keyBytes: Uint8Array): Promise<SymmetricKey> {
        throw new Error('Function not implemented.');
      },
      exportPublicKeyPem: function (key: PublicKey): Promise<string> {
        throw new Error('Function not implemented.');
      },
      exportPublicKeyJwk: function (key: PublicKey): Promise<JsonWebKey> {
        throw new Error('Function not implemented.');
      },
      splitSymmetricKey: function (key: SymmetricKey, numShares: number): Promise<SymmetricKey[]> {
        throw new Error('Function not implemented.');
      },
      mergeSymmetricKeys: function (shares: SymmetricKey[]): Promise<SymmetricKey> {
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
