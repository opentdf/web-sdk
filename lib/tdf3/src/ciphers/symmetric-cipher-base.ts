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
    // @ts-ignore
    return this.cryptoService.generateInitializationVector(this.ivLength);
  }

  generateKey() {
    // @ts-ignore
    return this.cryptoService.generateKey(this.keyLength);
  }

  abstract encrypt(payload: Binary, key: Binary, iv: Binary): Promise<EncryptResult>;

  abstract decrypt(payload: Binary, key: Binary, iv?: Binary): Promise<DecryptResult>;
}
