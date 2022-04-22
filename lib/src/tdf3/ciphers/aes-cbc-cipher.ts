import { Algorithms } from './algorithms';
import { SymmetricCipher } from './symmetric-cipher-base';

import type { Binary } from '../binary';
import type { CryptoService, DecryptResult, EncryptResult } from '../crypto/declarations';

const KEY_LENGTH = 32;
const IV_LENGTH = 16;

export class AesCbcCipher extends SymmetricCipher {
  constructor(cryptoService: CryptoService) {
    super(cryptoService);
    this.name = 'AES-256-CBC';
    this.ivLength = IV_LENGTH;
    this.keyLength = KEY_LENGTH;
  }

  override async encrypt(payload: Binary, key: Binary, iv: Binary): Promise<EncryptResult> {
    return this.cryptoService.encrypt(payload, key, iv, Algorithms.AES_256_CBC);
  }

  override async decrypt(payload: Binary, key: Binary, iv: Binary): Promise<DecryptResult> {
    return this.cryptoService.decrypt(payload, key, iv, Algorithms.AES_256_CBC);
  }
}
