import { Binary } from '../binary.js';
import { type AlgorithmUrn } from '../ciphers/algorithms.js';

export type EncryptResult = {
  /** Encrypted payload. */
  payload: Binary;
  /** Auth tag, if generated/ */
  authTag?: Binary;
};

export type DecryptResult = {
  payload: Binary;
};

/**
 * PEM formatted keypair.
 */
export type PemKeyPair = {
  publicKey: string;
  privateKey: string;
};

/**
 * The minimum acceptable asymetric key size, currently 2^11.
 */
export const MIN_ASYMMETRIC_KEY_SIZE_BITS = 2048;

/**
 * Supported asymmetric signing algorithm.
 * Currently limited to RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
 */
export type SigningAlgorithm = 'RS256';

/**
 * Supported hash algorithm.
 * Currently limited to SHA-256.
 */
export type HashAlgorithm = 'SHA-256';

export type AnyKeyPair = PemKeyPair | CryptoKeyPair;

export type CryptoService = {
  /** Track which crypto implementation we are using */
  name: string;

  /** Default algorithm identifier. */
  method: AlgorithmUrn;

  /** Convert or narrow from AnyKeyPair to PemKeyPair */
  cryptoToPemPair: (keys: AnyKeyPair) => Promise<PemKeyPair>;

  /**
   * Try to decrypt content with the default or handed algorithm. Throws on
   * most failure, if auth tagging is implemented for example.
   */
  decrypt: (
    payload: Binary,
    key: Binary,
    iv: Binary,
    algorithm?: AlgorithmUrn,
    authTag?: Binary
  ) => Promise<DecryptResult>;

  decryptWithPrivateKey: (encryptedPayload: Binary, privateKey: string) => Promise<Binary>;

  /**
   * Encrypt content with the default or handed algorithm.
   */
  encrypt: (
    payload: Binary,
    key: Binary,
    iv: Binary,
    algorithm?: AlgorithmUrn
  ) => Promise<EncryptResult>;

  encryptWithPublicKey: (payload: Binary, publicKey: string) => Promise<Binary>;

  /** Get length random bytes as a hex-encoded string. */
  generateInitializationVector: (length?: number) => Promise<string>;

  /** Get length random bytes as a hex-encoded string. */
  generateKey: (length?: number) => Promise<string>;

  /**
   * Generate an RSA key pair
   * @param size in bits, defaults to a reasonable size for the default method
   */
  generateKeyPair: (size?: number) => Promise<AnyKeyPair>;

  generateSigningKeyPair: () => Promise<AnyKeyPair>;

  /**
   * Compute HMAC-SHA256 of content using key.
   * @param key - Hex-encoded key bytes (e.g., "0a1b2c...")
   * @param content - Hex-encoded content bytes to authenticate
   * @returns Hex-encoded HMAC result
   *
   * IMPORTANT: Both input and output use lowercase hex encoding.
   * Implementations MUST follow this contract exactly.
   */
  hmac: (key: string, content: string) => Promise<string>;

  randomBytes: (byteLength: number) => Promise<Uint8Array>;

  /** Compute the hex-encoded SHA hash of a UTF-16 encoded string. */
  sha256: (content: string) => Promise<string>;

  /**
   * Sign data with an RSA private key.
   * @param data - Data to sign
   * @param privateKeyPem - PEM-encoded RSA private key (PKCS#8 format)
   * @param algorithm - RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
   */
  sign: (data: Uint8Array, privateKeyPem: string, algorithm: SigningAlgorithm) => Promise<Uint8Array>;

  /**
   * Verify signature with an RSA public key.
   * @param data - Original data that was signed
   * @param signature - Signature to verify
   * @param publicKeyPem - PEM-encoded RSA public key (SPKI format)
   * @param algorithm - Must match algorithm used for signing
   */
  verify: (data: Uint8Array, signature: Uint8Array, publicKeyPem: string, algorithm: SigningAlgorithm) => Promise<boolean>;

  /**
   * Compute hash digest.
   * @param algorithm - Hash algorithm to use
   * @param data - Data to hash
   */
  digest: (algorithm: HashAlgorithm, data: Uint8Array) => Promise<Uint8Array>;

  /**
   * Extract PEM public key from X.509 certificate or return PEM key as-is.
   *
   * Used to normalize KAS public keys which may be provided as either:
   * - X.509 certificates (-----BEGIN CERTIFICATE-----)
   * - Raw PEM public keys (-----BEGIN PUBLIC KEY-----)
   *
   * X.509 certificates are self-describing (algorithm is in cert metadata),
   * so no algorithm parameter is needed. Output is always SPKI-format PEM.
   *
   * @param certOrPem - PEM-encoded public key or X.509 certificate
   * @returns PEM-encoded public key (SPKI format)
   * @throws Error if input is not valid PEM or certificate
   */
  extractPublicKeyPem: (certOrPem: string) => Promise<string>;
};
