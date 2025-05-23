import { Binary } from '../binary.js';
import { Algorithms } from './algorithms.js';
import { SymmetricCipher } from './symmetric-cipher-base.js';
import { concatUint8 } from '../utils/index.js';

import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
} from '../crypto/declarations.js';

const KEY_LENGTH = 32;
const IV_LENGTH = 12;

type ProcessGcmPayload = {
  payload: Binary;
  payloadIv: Binary;
  payloadAuthTag: Binary;
};
// Should this be a Binary, Buffer, or... both?
function processGcmPayload(source: ArrayBuffer): ProcessGcmPayload {
  // Read the 12 byte IV from the beginning of the stream
  const payloadIv = Binary.fromArrayBuffer(source.slice(0, 12));

  // Slice the final 16 bytes of the buffer for the authentication tag
  const payloadAuthTag = Binary.fromArrayBuffer(source.slice(-16));

  return {
    payload: Binary.fromArrayBuffer(source.slice(12, -16)),
    payloadIv,
    payloadAuthTag,
  };
}

export class AesGcmCipher extends SymmetricCipher {
  constructor(cryptoService: CryptoService) {
    super(cryptoService);
    this.name = 'AES-256-GCM';
    this.ivLength = IV_LENGTH;
    this.keyLength = KEY_LENGTH;
  }

  /**
   * Encrypts the payload using AES w/ GCM mode.  This function will take the
   * result from the crypto service and construct the payload automatically from
   * it's parts.  There is no need to process the payload.
   */
  override async encrypt(payload: Binary, key: Binary, iv: Binary): Promise<EncryptResult> {
    const toConcat: Uint8Array[] = [];
    const result = await this.cryptoService.encrypt(payload, key, iv, Algorithms.AES_256_GCM);
    toConcat.push(new Uint8Array(iv.asArrayBuffer()));
    toConcat.push(new Uint8Array(result.payload.asArrayBuffer()));
    if (result.authTag) {
      toConcat.push(new Uint8Array(result.authTag.asArrayBuffer()));
    }
    result.payload = Binary.fromArrayBuffer(concatUint8(toConcat).buffer);
    return result;
  }

  /**
   * Encrypts the payload using AES w/ CBC mode
   * @returns
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  override async decrypt(buffer: ArrayBuffer, key: Binary, iv?: Binary): Promise<DecryptResult> {
    const { payload, payloadIv, payloadAuthTag } = processGcmPayload(buffer);

    return this.cryptoService.decrypt(
      payload,
      key,
      payloadIv,
      Algorithms.AES_256_GCM,
      payloadAuthTag
    );
  }
}
