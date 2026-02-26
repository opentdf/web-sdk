import { type Binary } from '../binary.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type SymmetricKey,
} from '../crypto/declarations.js';
import { encodeArrayBuffer as hexEncode } from '../../../src/encodings/hex.js';

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
    return hexEncode(bytes.buffer);
  }

  async generateKey(): Promise<SymmetricKey> {
    if (!this.keyLength) {
      throw Error('No key length');
    }
    return this.cryptoService.generateKey(this.keyLength);
  }

  abstract encrypt(payload: Binary, key: SymmetricKey, iv: Binary): Promise<EncryptResult>;

  abstract decrypt(payload: Uint8Array, key: SymmetricKey, iv?: Binary): Promise<DecryptResult>;
}
