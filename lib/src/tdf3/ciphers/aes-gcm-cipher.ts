import { Binary } from '../binary';
import { Algorithms } from './algorithms';
import { SymmetricCipher } from './symmetric-cipher-base';

import type { CryptoService, DecryptResult, EncryptResult } from '../crypto/declarations';

const KEY_LENGTH = 32;
const IV_LENGTH = 12;

function processGcmPayload(buffer) {
  // Read the 12 byte IV from the beginning of the stream
  const payloadIv = Binary.fromBuffer(buffer.slice(0, 12));

  // Slice the final 16 bytes of the buffer for the authentication tag
  const payloadAuthTag = Binary.fromBuffer(buffer.slice(-16));

  return {
    payload: Binary.fromBuffer(buffer.slice(12, -16)),
    payloadIv,
    payloadAuthTag,
  };
}

class AesGcmCipher extends SymmetricCipher {
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
   * @returns {Object}
   */
  override async encrypt(payload: Binary, key: Binary, iv: Binary): Promise<EncryptResult> {
    const result = await this.cryptoService.encrypt(payload, key, iv, Algorithms.AES_256_GCM);
    const ivBuffer = iv.asBuffer();
    const authTagBuffer = result.authTag.asBuffer();

    result.payload = Binary.fromBuffer(
      Buffer.concat([ivBuffer, result.payload.asBuffer(), authTagBuffer])
    );

    return result;
  }

  /**
   * Encrypts the payload using AES w/ CBC mode
   * @returns
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  override async decrypt(binary: Binary, key: Binary, iv?: Binary): Promise<DecryptResult> {
    const { payload, payloadIv, payloadAuthTag } = processGcmPayload(binary);

    return this.cryptoService.decrypt(
      payload,
      key,
      payloadIv,
      Algorithms.AES_256_GCM,
      payloadAuthTag
    );
  }
}

export { AesGcmCipher };
