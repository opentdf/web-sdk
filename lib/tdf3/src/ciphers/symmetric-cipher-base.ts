import type { Binary } from '../binary.js';
import type { CryptoService, DecryptResult, EncryptResult } from '../crypto/declarations.js';

export abstract class SymmetricCipher {
  cryptoService: CryptoService;

  name?: string;

  ivLength?: number;

  keyLength?: number;

  constructor(cryptoService: CryptoService) {
    this.cryptoService = cryptoService;
  }

  generateInitializationVector(): string {
    if (!this.ivLength) {
      throw Error('No iv length');
    }
    return this.cryptoService.generateInitializationVector(this.ivLength);
  }

  generateKey(): string {
    if (!this.keyLength) {
      throw Error('No key length');
    }
    return this.cryptoService.generateKey(this.keyLength);
  }

  abstract encrypt(payload: Binary, key: Binary, iv: Binary): Promise<EncryptResult>;

  abstract decrypt(payload: Buffer, key: Binary, iv?: Binary): Promise<DecryptResult>;
}
