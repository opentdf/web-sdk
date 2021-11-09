import Header from './Header.js';
import { getBitLength } from '../models/Ciphers.js';
import InvalidPayloadError from '../errors/InvalidPayloadError.js';

/**
 * Payload
 *
 * The payload section of the nanotdf contains the ciphertext that is protected by the policy defined in the Header.
 * The structure of the Payload is as follows:
 *
 * | Section               | Minimum Length (B) | Maximum Length (B) |
 * |-----------------------|--------------------|--------------------|
 * | Length                | 3                  | 3                  |
 * | IV                    | 3                  | 3                  |
 * | Ciphertext            | 0                  | 16777204           |
 * | Payload MAC (AuthTag) | 8                  | 32                 |
 */
export default class Payload {
  static LENGTH_LEN = 3;
  static IV_LEN = 3;
  static MIN_LENGTH = 11;
  static MAX_NANO_TDF_ENCRYPT_PAYLOAD_SIZE = 16777216; // 3 bytes unsigned int.

  public iv: Uint8Array;
  public ciphertext: Uint8Array;
  public authTag: Uint8Array;
  public ciphertextWithAuthTag: Uint8Array;

  /**
   * Parse the payload
   *
   * Returns a new Payload object and the next offset
   *
   * @param buff Uint8Array
   */
  static parse(
    header: Header,
    buff: Uint8Array,
    legacyTDF = false
  ): { payload: Payload; offset: number } {
    let offset = 0;
    const authTagByteLength = getBitLength(header.symmetricCipher) / 8;

    /**
     * Length
     *
     * This 3 byte unsigned integer dictates the length of the subsequent ciphertext section.
     *
     * NOTE: it includes the IV + Ciphertext + Auth Tag. To get the Auth Tag length you have to subtract the other
     * lengths
     */
    // TODO: This will not work in Big Endian host environments
    const length = (buff[offset] << 16) + (buff[offset + 1] << 8) + buff[offset + 2];
    const ciphertextLength = length - Payload.IV_LEN - authTagByteLength;
    offset += Payload.LENGTH_LEN;

    const inRange = length >= this.MIN_LENGTH && length <= this.MAX_NANO_TDF_ENCRYPT_PAYLOAD_SIZE;

    if (!inRange) {
      throw new InvalidPayloadError(inRange);
    }

    /**
     * Parse IV
     *
     * The IV used for encryption. This value is a byte array containing the IV. This IV must never be reused with the
     * same symmetric key. Also, to support an extremely compacted version of the nanotdf the IV value 00 00 00 is
     * reserved for use with an encrypted policy.
     */
    let iv = buff.subarray(offset, offset + Payload.IV_LEN);
    offset += Payload.IV_LEN;

    if (iv.byteLength != 3) {
      throw new InvalidPayloadError(inRange);
    }

    if (!legacyTDF) {
      const actuallIV = new Uint8Array(12).fill(0);

      // The the iv from payload to lower-order bits
      actuallIV.set(iv, 9);

      // update the iv
      iv = actuallIV;
    }

    /**
     * Parse Ciphertext w/ Auth Tag
     */
    const ciphertextWithAuthTag = buff.subarray(
      offset,
      offset + ciphertextLength + authTagByteLength
    );

    if (ciphertextWithAuthTag.byteLength + Payload.LENGTH_LEN !== length) {
      throw new InvalidPayloadError(inRange);
    }

    /**
     * Parse Ciphertext
     *
     * The byte array of the ciphertext that is protected in the nanotdf. The encryption method used to create or decrypt
     * the ciphertext is defined in the Key Access object in the header.
     */
    const ciphertext = buff.subarray(offset, offset + ciphertextLength);
    offset += ciphertextLength;

    /**
     * Auth Tag
     *
     * GMAC = 8 byte
     * ECDSA = size of curve
     *
     * The MAC of the payload. The Size of this MAC is determined by the Encryption Method Enum used in the Symmetric and
     * Payload Config object in the header.
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3314-symmetric-and-payload-config
     */
    const authTag = buff.subarray(offset, offset + authTagByteLength);
    offset += authTagByteLength;

    return {
      payload: new Payload(iv, ciphertext, authTag, ciphertextWithAuthTag),
      offset,
    };
  }

  constructor(
    iv: Uint8Array,
    ciphertext: Uint8Array,
    authTag: Uint8Array,
    ciphertextWithAuthTag?: Uint8Array
  ) {
    this.iv = iv;
    this.ciphertext = ciphertext;
    this.authTag = authTag;

    // If ciphertextWithAuthTag is not set then combine it
    // Ideally it is set so an additional buffer is not needed
    if (ciphertextWithAuthTag === undefined) {
      this.ciphertextWithAuthTag = new Uint8Array(ciphertext.length + authTag.length);
      this.ciphertextWithAuthTag.set(ciphertext);
      this.ciphertextWithAuthTag.set(authTag, ciphertext.length);
    } else {
      this.ciphertextWithAuthTag = ciphertextWithAuthTag;
    }
  }

  /**
   * Length
   *
   * @returns { number } Length of signature
   */
  get length(): number {
    return (
      // Bytes(3) to hold the length of the payload
      3 +
      // Length of the IV
      this.iv.length +
      // Length of the ciphertext
      this.ciphertext.length +
      // Length of the auth tag
      this.authTag.length
    );
  }

  /**
   * Copy the contents of the signature to buffer
   */
  copyToBuffer(buffer: Uint8Array): void {
    if (this.length > buffer.length) {
      throw new Error('Invalid buffer size to copy payload');
    }

    const lengthOfEncryptedPayload = this.iv.length + this.ciphertext.length + this.authTag.length;
    if (lengthOfEncryptedPayload > Payload.MAX_NANO_TDF_ENCRYPT_PAYLOAD_SIZE) {
      throw new Error("TDF encrypted payload can't be more that 2^24");
    }

    const lengthAsUint32 = new Uint32Array(1);
    lengthAsUint32[0] = lengthOfEncryptedPayload;

    const lengthAsUint24 = new Uint8Array(lengthAsUint32.buffer);

    // NOTE: We are only interested in only first 3 bytes.
    const payloadSizeAsBg = new Uint8Array(3);
    payloadSizeAsBg[0] = lengthAsUint24[2];
    payloadSizeAsBg[1] = lengthAsUint24[1];
    payloadSizeAsBg[2] = lengthAsUint24[0];

    buffer.set(payloadSizeAsBg, 0);
    buffer.set(this.iv, payloadSizeAsBg.length);
    buffer.set(this.ciphertext, payloadSizeAsBg.length + this.iv.length);
    buffer.set(this.authTag, payloadSizeAsBg.length + this.iv.length + this.ciphertext.length);
  }
}
