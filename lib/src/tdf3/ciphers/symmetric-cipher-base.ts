import type { Binary } from '../binary';
import type { CryptoService, DecryptResult, EncryptResult } from '../crypto/declarations';

export abstract class SymmetricCipher {
  cryptoService: CryptoService;

  name?: string;

  ivLength?: number;

  keyLength?: number;

  constructor(cryptoService: CryptoService) {
    this.cryptoService = cryptoService;
  }

  generateInitializationVector() {
    return this.cryptoService.generateInitializationVector(this.ivLength);
  }

  generateKey() {
    return this.cryptoService.generateKey(this.keyLength);
  }

  abstract encrypt(payload: Binary, key: Binary, iv: Binary): Promise<EncryptResult>;

  abstract decrypt(payload: Binary, key: Binary, iv?: Binary): Promise<DecryptResult>;
}
