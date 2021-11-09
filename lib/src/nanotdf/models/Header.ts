// Models
import { getBitLength } from './Ciphers.js';
import ResourceLocator from './ResourceLocator.js';
import PolicyFactory from './Policy/PolicyFactory.js';
// Interfaces
import PolicyInterface from '../interfaces/PolicyInterface.js';
// Enum
import CipherEnum from '../enum/CipherEnum.js';
import CurveNameEnum from '../enum/CurveNameEnum.js';
// Helpers
import { lengthOfPublicKey } from '../helpers/calculateByCurve.js';
import DefaultParams from './DefaultParams.js';
// Errors
import InvalidEphemeralKeyError from '../errors/InvalidEphemeralKeyError.js';

/**
 * NanoTDF Header
 *
 * The header section is intended to be sent to a KAS and is used by the KAS to derive the decryption key that can
 * decrypts the nanotdf's payload. The Header is structured as follows:
 *
 * | Section                | Minimum Length (B) | Maximum Length (B) |
 * |------------------------|--------------------|--------------------|
 * | Magic Number + Version | 3                  | 3                  |
 * | KAS (resource locator) | 3                  | 257                |
 * | ECC Mode               | 1                  | 1                  |
 * | Payload + Sig Mode     | 1                  | 1                  |
 * | Policy                 | 3                  | 257                |
 * | Ephemeral Key          | 33                 | 67                 |
 *
 */
export default class Header {
  // Magic Number & Version
  static readonly MAGIC_NUMBER_VERSION_BYTE_OFF = 0;
  static readonly MAGIC_NUMBER_VERSION_BYTE_LEN = 3;
  static readonly MAGIC_NUMBER_OFFSET = 0;
  static readonly MAGIC_NUMBER_LENGTH = 18;

  // ECC & Binding Mode
  static readonly ECC_BINDING_MODE_BYTE_LEN = 1;
  static readonly USE_ECDSA_BINDING_BIT_OFF = 0;
  static readonly EPHEMERAL_ECC_CURVE_NAME_BIT_OFF = -3;

  // Symmetric & Payload Config
  static readonly SYMMETRIC_PAYLOAD_CONFIG_BYTE_LEN = 1;
  static readonly HAS_SIGNATURE_BIT_OFF = 1;
  static readonly HAS_SIGNATURE_BIT_LEN = 1;
  static readonly SIGNATURE_ECC_CURVE_NAME_BIT_OFF = 1;
  static readonly SIGNATURE_ECC_CURVE_NAME_BIT_LEN = 3;
  static readonly SYMMETRIC_CIPHER_BIT_OFF = 4;
  static readonly SYMMETRIC_CIPHER_BIT_LEN = 4;

  // Magic Number & Version
  public magicNumberVersion: Uint8Array = DefaultParams.magicNumberVersion;

  // KAS Resource Locator
  public kas: ResourceLocator;

  // ECC & Binding Mode
  public useECDSABinding: boolean = DefaultParams.ecdsaBinding;
  public ephemeralCurveName: CurveNameEnum = DefaultParams.ephemeralCurveName;

  // Symmetric & Payload Config
  public hasSignature: boolean = DefaultParams.signature;
  public signatureCurveName: CurveNameEnum = DefaultParams.signatureCurveName;
  public symmetricCipher: CipherEnum = DefaultParams.symmetricCipher;
  // Auth tag length (in bits) is not part of the spec, but is needed for decrypt
  public authTagLength: number;

  // Policy
  public policy: PolicyInterface;

  // Ephemeral Public Key
  public ephemeralPublicKey: Uint8Array;

  static parse(buff: Uint8Array, legacyTDF = false) {
    let offset = 0;

    /**
     * Magic number and version
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3311-magic-number--version
     */
    // Convert to ascii
    const magicNumberVersion = buff.subarray(
      Header.MAGIC_NUMBER_VERSION_BYTE_OFF,
      Header.MAGIC_NUMBER_VERSION_BYTE_LEN
    );
    offset += Header.MAGIC_NUMBER_VERSION_BYTE_LEN;

    /**
     * KAS Resource Locator
     *
     * KAS is a typeof Resource Locator
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3312-kas
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#341-resource-locator
     */
    const kas = new ResourceLocator(buff.subarray(offset));
    offset += kas.length;

    /**
     * ECC & Binding Mode
     *
     * This section contains a 1-byte bitfield describing the ECC Params and Policy binding strategy to use.
     * The Policy Binding strategy is either using a 64-bit GMAC (using AES-256-GCM) tag or an ECDSA signature.
     * The signature size depends on the size of ECC Params used. The nanotdf at this time only supports methods that
     * involve Elliptic Curve Cryptography. The fields are structured as follows:
     *
     * | Section                   | Bit Length | Bit start index |
     * |---------------------------|------------|-----------------|
     * | USE_ECDSA_BINDING         | 1          | 7               |
     * | UNUSED                    | 4          | 3               |
     * | Ephemeral ECC Params Enum | 3          | 0               |
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3313-ecc-and-binding-mode
     */
    const eccBindingModeDV = buff.subarray(offset, offset + Header.ECC_BINDING_MODE_BYTE_LEN);
    const useECDSABinding = eccBindingModeDV[0] >> 7 === 1; // Last bit
    const ephemeralCurveName = eccBindingModeDV[0] & 0x7; // First 3 bits
    offset += Header.ECC_BINDING_MODE_BYTE_LEN;

    /**
     * Symmetric & payload config
     *
     * This section contains a 1 byte data structure composed of bitfields that describe the symmetric ciphers for
     * encrypted payloads. This cipher applies to both the Payload and the Policy of the nanotdf. The fields are as
     * follows:
     *
     * | Section               | Bit Length | Bit start index |
     * |-----------------------|------------|-----------------|
     * | HAS_SIGNATURE         | 1          | 7               |
     * | Signature ECC Mode    | 3          | 4               |
     * | Symmetric Cipher Enum | 4          | 0               |
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3314-symmetric-and-payload-config
     */
    const symmetricPayloadDV = buff.subarray(offset, offset + Header.ECC_BINDING_MODE_BYTE_LEN);
    const hasSignature = symmetricPayloadDV[0] >> 7 === 1; // Last bit
    const signatureCurveName = (symmetricPayloadDV[0] >> 4) & 0x7; // Middle 3 bits
    const symmetricCipher = symmetricPayloadDV[0] & 0xf; // First 4 bits
    offset += Header.SYMMETRIC_PAYLOAD_CONFIG_BYTE_LEN;

    /**
     * Policy
     *
     * This section contains a Policy object. The data contained in the Policy allows for definition flexible
     * definitions of a policy including a policy by reference, or an embedded policy. Refer to the Policy object's
     * definition in Section 3.4.2
     *
     * The structure of the Policy is as follows:
     *
     * | Section   | Minimum Length (B) | Maximum Length (B) |
     * |-----------|--------------------|--------------------|
     * | Type Enum | 1                  | 1                  |
     * | Body      | 3                  | 257                |
     * | Binding   | 8                  | 132                |
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3315-policy
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#342-policy
     */
    const { policy, offset: nextOffset } = PolicyFactory.parse(
      buff.subarray(offset),
      useECDSABinding,
      ephemeralCurveName
    );
    offset += nextOffset;

    /**
     * Ephemeral public key
     *
     * This section contains a Key object. The size of the key is determined by the Encryption Method Section.
     *
     * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3316-key
     */
    // TODO: Resolve where offset isn't adding 1 byte
    const ephemeralPublicKeyLength = lengthOfPublicKey(ephemeralCurveName) + 1;
    const ephemeralPublicKey = buff.subarray(offset, offset + ephemeralPublicKeyLength);
    offset += ephemeralPublicKeyLength;

    // Check if the ephemeral public key length is not the same length
    if (ephemeralPublicKey.byteLength !== ephemeralPublicKeyLength) {
      throw new InvalidEphemeralKeyError();
    }

    const header = new Header(
      magicNumberVersion,
      kas,
      useECDSABinding,
      ephemeralCurveName,
      hasSignature,
      signatureCurveName,
      symmetricCipher,
      policy,
      ephemeralPublicKey
    );

    return {
      header,
      offset,
    };
  }

  //Ephemeral Public Key
  // protected _ephemeralPublicKey: string | null = null;

  constructor(
    magicNumberVersion: Uint8Array,
    kas: ResourceLocator,
    useECDSABinding: boolean,
    ephemeralCurveName: CurveNameEnum,
    hasSignature: boolean,
    signatureCurveName: CurveNameEnum,
    symmetricCipher: CipherEnum,
    policy: PolicyInterface,
    ephemeralPublicKey: Uint8Array
  ) {
    this.magicNumberVersion = magicNumberVersion;
    this.kas = kas;
    this.useECDSABinding = useECDSABinding;
    this.ephemeralCurveName = ephemeralCurveName;
    this.hasSignature = hasSignature;
    this.signatureCurveName = signatureCurveName;
    this.symmetricCipher = symmetricCipher;
    this.policy = policy;
    this.ephemeralPublicKey = ephemeralPublicKey;

    // Auth tag length in bits (i.e. AES GCM 64 bit)
    this.authTagLength = getBitLength(this.symmetricCipher);
  }

  /**
   * Copy the contents of the header to buffer
   */
  copyToBuffer(buffer: Uint8Array): void {
    if (this.length > buffer.length) {
      throw new Error('Invalid buffer size to copy tdf header');
    }

    let offset = 0;

    // Write Magic number and version
    buffer.set(this.magicNumberVersion, 0);
    offset += this.magicNumberVersion.length;

    // Write kas resource locator
    const kasResourceLocatorBuf = this.kas.toBuffer();
    buffer.set(kasResourceLocatorBuf, offset);
    offset += kasResourceLocatorBuf.length;

    // Write ECC & Binding Mode
    const ecdsaBinding = this.useECDSABinding ? 1 : 0;
    const eccBingingMode = (ecdsaBinding << 7) | this.ephemeralCurveName;
    const eccBingingModeAsByte = new Uint8Array(1);
    eccBingingModeAsByte[0] = eccBingingMode;
    buffer.set(eccBingingModeAsByte, offset);
    offset += eccBingingModeAsByte.length;

    // Write symmetric & payload config
    const isSignatureEnable = this.hasSignature ? 1 : 0;
    const symmetricPayloadConfig =
      (isSignatureEnable << 7) | this.signatureCurveName | this.symmetricCipher;
    const symmetricPayloadConfigAsByte = new Uint8Array(1);
    symmetricPayloadConfigAsByte[0] = symmetricPayloadConfig;
    buffer.set(symmetricPayloadConfigAsByte, offset);
    offset += symmetricPayloadConfigAsByte.length;

    // Write the policy
    const policyBuffer = this.policy.toBuffer();
    buffer.set(policyBuffer, offset);
    offset += policyBuffer.length;

    // Write the ephemeral public key
    buffer.set(this.ephemeralPublicKey, offset);
  }

  /**
   * Length
   *
   * @returns { number } Length of header
   */
  get length(): number {
    return (
      // Length of the magic number and version
      this.magicNumberVersion.length +
      // Length of the KAS resource locator
      this.kas.length +
      // ECC & Binding Mode - 1 Bytes
      1 +
      // symmetric & payload config - 1 Bytes
      1 +
      // Length of the policy
      this.policy.getLength() +
      // Length of the ephemeral public key
      this.ephemeralPublicKey.length
    );
  }

  /**
   * Return nanoTDF header as buffer
   *
   * Warning: This method will allocate memory of length of the header, use
   * copyToBuffer() when copy is not needed.
   */
  toBuffer(): ArrayBuffer {
    const arrayBuffer = new ArrayBuffer(this.length);
    const buffer = new Uint8Array(arrayBuffer);
    this.copyToBuffer(buffer);
    return arrayBuffer;
  }

  /**
   * Get KAS Rewrap URL
   */
  getKasRewrapUrl(): string {
    try {
      return `${this.kas.getUrl()}/v2/rewrap`;
    } catch (e) {
      throw new Error(`Cannot construct KAS Rewrap URL: ${e.message}`);
    }
  }
}
