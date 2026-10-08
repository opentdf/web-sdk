import { type Binary } from '../binary.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type SymmetricKey,
} from '../crypto/declarations.js';
import { encodeArrayBuffer as hexEncode } from '../../../src/encodings/hex.js';
import { toArrayBuffer } from '../utils/index.js';
import { ConfigurationError } from '../../../src/errors.js';

export abstract class SymmetricCipher {
  cryptoService: CryptoService;

  name?: string;

  ivLength?: number;

  keyLength?: number;

  constructor(cryptoService: CryptoService) {
    this.cryptoService = cryptoService;
  }

  async generateInitializationVector(): Promise<string> {
    if (!this.ivLength) {
      throw Error('No iv length');
    }
    const bytes = await this.cryptoService.randomBytes(this.ivLength);
    return hexEncode(toArrayBuffer(bytes));
  }

  async generateKey(): Promise<SymmetricKey> {
    if (!this.keyLength) {
      throw Error('No key length');
    }
    return this.cryptoService.generateKey(this.keyLength);
  }

  /**
   * Exact number of bytes {@link encrypt} returns for `plaintextSize` bytes of input.
   *
   * Concrete rather than `abstract` so duck-typed ciphers written against
   * prior releases satisfy this class structurally.
   */
  encryptedPayloadSize(plaintextSize: number): number {
    void plaintextSize;
    throw new ConfigurationError(
      `Cipher [${this.name}] does not implement encryptedPayloadSize; it cannot be used to write a TDF`
    );
  }

  abstract encrypt(payload: Binary, key: SymmetricKey, iv: Binary): Promise<EncryptResult>;

  abstract decrypt(
    payload: ArrayBuffer | Uint8Array,
    key: SymmetricKey,
    iv?: Binary
  ): Promise<DecryptResult>;
}
