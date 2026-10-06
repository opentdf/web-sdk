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
   * Length of the buffer {@link encrypt} returns for a `plaintextSize`-byte
   * input. This must be exact, not an upper bound: the writer records it as
   * the manifest's `encryptedSegmentSizeDefault`, and a reader that trusts that
   * field over the per-segment sizes will slice the payload at the wrong
   * offsets.
   *
   * Concrete rather than `abstract` so that a duck-typed cipher written against
   * an older release still satisfies this class structurally; such a cipher
   * fails here with a named error instead of an undiagnosable `TypeError`.
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
