import { Binary } from '../binary.js';
import { Algorithms } from './algorithms.js';
import { SymmetricCipher } from './symmetric-cipher-base.js';
import { decryptBufferSource } from '../crypto/core/symmetric.js';
import { concatUint8, toArrayBuffer, toCryptoBytes } from '../utils/index.js';

import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type SymmetricKey,
} from '../crypto/declarations.js';

const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

type ProcessGcmPayload = {
  payload: Binary;
  payloadIv: Binary;
};
// Should this be a Binary, Buffer, or... both?
function processGcmPayload(source: ArrayBuffer): ProcessGcmPayload {
  // Read the 12 byte IV from the beginning of the stream
  const payloadIv = Binary.fromArrayBuffer(source.slice(0, 12));

  return {
    // WebCrypto AES-GCM expects ciphertext with the auth tag appended, so keep
    // the tag attached instead of splitting and re-concatenating it later.
    payload: Binary.fromArrayBuffer(source.slice(12)),
    payloadIv,
  };
}

export class AesGcmCipher extends SymmetricCipher {
  constructor(cryptoService: CryptoService) {
    super(cryptoService);
    this.name = 'AES-256-GCM';
    this.ivLength = IV_LENGTH;
    this.keyLength = KEY_LENGTH;
  }

  override encryptedPayloadSize(plaintextSize: number): number {
    return IV_LENGTH + plaintextSize + AUTH_TAG_LENGTH;
  }

  /**
   * Encrypts the payload using AES w/ GCM mode.  This function will take the
   * result from the crypto service and construct the payload automatically from
   * it's parts.  There is no need to process the payload.
   */
  override async encrypt(payload: Binary, key: SymmetricKey, iv: Binary): Promise<EncryptResult> {
    const toConcat: Uint8Array[] = [];
    const result = await this.cryptoService.encrypt(payload, key, iv, Algorithms.AES_256_GCM);
    toConcat.push(new Uint8Array(iv.asArrayBuffer()));
    toConcat.push(new Uint8Array(result.payload.asArrayBuffer()));
    if (result.authTag) {
      toConcat.push(new Uint8Array(result.authTag.asArrayBuffer()));
    }
    result.payload = Binary.fromArrayBuffer(toArrayBuffer(concatUint8(toConcat)));
    return result;
  }

  /**
   * Encrypts the payload using AES w/ CBC mode
   * @returns
   */

  override async decrypt(
    buffer: ArrayBuffer | Uint8Array,
    key: SymmetricKey,
    _iv?: Binary
  ): Promise<DecryptResult> {
    void _iv;
    const input = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

    if (this.cryptoService.name === 'BrowserNativeCryptoService') {
      return decryptBufferSource(
        toCryptoBytes(input.subarray(12)),
        key,
        toCryptoBytes(input.subarray(0, 12)),
        Algorithms.AES_256_GCM
      );
    }

    const { payload, payloadIv } = processGcmPayload(toArrayBuffer(input));

    return this.cryptoService.decrypt(payload, key, payloadIv, Algorithms.AES_256_GCM);
  }
}
