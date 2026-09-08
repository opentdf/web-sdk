import { type Binary } from '../binary.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type SymmetricKey,
} from '../crypto/declarations.js';

export abstract class SymmetricCipher {
  cryptoService: CryptoService;

  name?: string;

  ivLength?: number;

  keyLength?: number;

  constructor(cryptoService: CryptoService) {
    this.cryptoService = cryptoService;
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
   * the manifest's `encryptedSegmentSizeDefault`, and readers seek by it, so
   * an over- or under-estimate produces a TDF whose segment offsets are wrong
   * in every SDK that trusts the field.
   *
   * For AES-GCM the answer is `ivLength + plaintextSize + tagLength`, because
   * the mode is a stream cipher with a fixed-width tag. A block-mode cipher
   * would instead have to round up to the block size and drop the tag term.
   */
  abstract encryptedPayloadSize(plaintextSize: number): number;

  abstract encrypt(payload: Binary, key: SymmetricKey, iv: Binary): Promise<EncryptResult>;

  abstract decrypt(
    payload: ArrayBuffer | Uint8Array,
    key: SymmetricKey,
    iv?: Binary
  ): Promise<DecryptResult>;
}
