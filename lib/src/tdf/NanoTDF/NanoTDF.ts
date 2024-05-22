enum CipherType {
  Aes256Gcm64, // Default cipher
  Aes256Gcm96,
  Aes256Gcm104,
  Aes256Gcm112,
  Aes256Gcm120,
  Aes256Gcm128,
}

/**
 * The Signature ECC Mode is used to determine the length of the signature at the end of a nanotdf. This, in
 * combination with the previous HAS_SIGNATURE section, describe the signature of the nanotdf. The following table
 * describes the valid values and the associated ECC Params.
 */
enum CurveName {
  Secp256R1,
  Secp384R1,
  Secp521R1,
}

export enum ResourceLocatorProtocol {
  Http,
  Https,
  Unreserverd,
  SharedResourceDirectory = 0xff,
}

export enum PolicyType {
  Remote,
  EmbeddedText,
  EmbeddedEncrypted, // Default policy
  EmbeddedEncryptedPKA, // Todo: Not implemented
}

/**
 * Resource Locator interface
 */
export interface ResourceLocator {
  protocol: ResourceLocatorProtocol;
  length: number;
  body: string;
}

/**
 * Policy interface
 */
export interface Policy {
  type: PolicyType;
  binding: Uint8Array;
}

/**
 * Remote policy interface
 */
export interface RemotePolicy extends Policy {
  protocol: ResourceLocatorProtocol;
  urn: string;
}

/**
 * Embedded policy interface
 */
export interface EmbeddedPolicy extends Policy {
  content: Uint8Array;
}

/**
 * Header interface
 */
export interface Header {
  // Magic Number & Version
  magicNumberVersion: Uint8Array;

  // KAS Resource Locator
  kas: ResourceLocator;

  // ECC & Binding Mode
  useECDSABinding: boolean;
  ephemeralCurveName: CurveName;

  // Symmetric & Payload Config
  hasSignature: boolean;
  signatureCurveName: CurveName;
  symmetricCipher: CipherType;
  // Auth tag length is not part of the spec, but is needed for decrypt
  authTagLength: number;

  // Policy
  policy: RemotePolicy | EmbeddedPolicy;

  // Ephemeral Public Key
  ephemeralPublicKey: Uint8Array;
}

/**
 * Payload interface
 */
export interface Payload {
  iv: Uint8Array;
  ciphertext: Uint8Array;
  authTag: Uint8Array;
  ciphertextAuthTag: Uint8Array;
}

/**
 * Signature interface
 */
export interface Signature {
  publicKey: Uint8Array;
  signature: Uint8Array;
}

/**
 * NanoTDF interface
 */
export interface NanoTDF {
  header: Header;
  payload: Payload;
  signature: Signature;
}
