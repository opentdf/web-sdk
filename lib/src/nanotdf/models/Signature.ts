import Header from './Header.js';
import { lengthOfPublicKey, lengthOfSignature } from '../helpers/calculateByCurve.js';

/**
 * NanoTDF Signature
 *
 * The signature section is an optional section that contains an ECDSA signature used to cryptographically bind the Header and Payload to a creator of the nanotdf. The key used for signing is the private key of the creator of the nanotdf. The ECC Params used for the signature are described in Section 3.3.1.4.2. The private key used for this signature is distinctly different than the ephemeral private key. This is a persistent key belonging to an individual, entity, or device that creates nanotdfs. The signature is used to authenticate the entire nanotdf and contains both the public key related to the creators private key and the resulting signature. The structure of this section:
 *
 * | Section    | Minimum Length (B) | Maximum Length (B) |
 * |------------|--------------------|--------------------|
 * | Public Key | 33                 | 67                 |
 * | Signature  | 64                 | 132                |
 *
 * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#333-signature
 */
export default class Signature {
  public publicKey: Uint8Array;
  public signature: Uint8Array;

  static parse(header: Header, buff: Uint8Array): { signature: Signature; offset: number } | never {
    let offset = 0;

    /**
     * Parse the public key
     *
     * This section contains the compressed public key of the private key used to sign the message.
     */
    // TODO: Resolve where offset is missing 1 byte
    const publicKeyLength = lengthOfPublicKey(header.signatureCurveName) + 1;
    const publicKey = buff.subarray(offset, offset + publicKeyLength);
    offset += publicKeyLength;

    /**
     * Parse signature
     *
     * This section contains the encoded `r` and `s` values of the ECDSA signature.
     *
     * ECDSA signatures are big endian encodings of the `r` and `s` values of an ECDSA signature.The length of `r` and `s`
     * values is determined by the ECC Mode used for the signature. The encoding for the signature is the big endian
     * encodings of R and S concatenated to each other. For example, `r = 1` and `s = 2` for an ECDSA signature of a
     * ecp256k1 key would be (line breaks and spaces are added for easier visualization):
     *
     * ```
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02
     * ```
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#52-ecdsa-signature-encoding
     */
    const signatureLength = lengthOfSignature(header.signatureCurveName);
    const signature = buff.subarray(offset, offset + signatureLength);
    offset += signatureLength;

    return { signature: new Signature(publicKey, signature), offset };
  }

  constructor(publicKey: Uint8Array, signature: Uint8Array) {
    this.publicKey = publicKey;
    this.signature = signature;
  }

  /**
   * Length
   *
   * @returns { number } Length of signature
   */
  get length(): number {
    return this.publicKey.length + this.signature.length;
  }

  /**
   * Copy the contents of the signature to buffer
   */
  copyToBuffer(buffer: Uint8Array): void {
    if (this.length > buffer.length) {
      throw new Error('Invalid buffer size to copy signature');
    }

    buffer.set(this.publicKey, 0);
    buffer.set(this.signature, this.publicKey.length);
  }
}
