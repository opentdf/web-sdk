import { expect } from 'chai';
import {
  type AlgorithmUrn,
  type Binary,
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type PemKeyPair,
} from '../../../tdf3/index.js';
import { Client } from '../../../tdf3/src/client/index.js';

describe('CryptoService DI', () => {
  it('Loads mock CryptoService', async () => {
    const cryptoService: CryptoService = {
      name: 'mock',
      method: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      cryptoToPemPair: function (keys: unknown): Promise<PemKeyPair> {
        throw new Error('Function not implemented.');
      },
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
      generateKeyPair: function (size?: number | undefined): Promise<CryptoKeyPair> {
        throw new Error('Function not implemented.');
      },
      generateSigningKeyPair: function (): Promise<CryptoKeyPair> {
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
});
