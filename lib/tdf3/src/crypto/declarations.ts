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
 * Elliptic curves supported for ECDH/ECDSA operations.
 */
export type ECCurve = 'P-256' | 'P-384' | 'P-521';

/**
 * Asymmetric signing algorithms (require PEM keys).
 */
export type AsymmetricSigningAlgorithm = 'RS256' | 'ES256' | 'ES384' | 'ES512';

/**
 * Symmetric signing algorithm (requires raw key bytes).
 */
export type SymmetricSigningAlgorithm = 'HS256';

/**
 * All supported signing algorithms.
 */
export type SigningAlgorithm = AsymmetricSigningAlgorithm | SymmetricSigningAlgorithm;

/**
 * Supported hash algorithms.
 */
export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Parameters for HKDF key derivation.
 */
export type HkdfParams = {
  /** Hash algorithm to use for HKDF. */
  hash: HashAlgorithm;
  /** Salt for HKDF (can be empty Uint8Array). */
  salt: Uint8Array;
  /** Optional info/context for HKDF. */
  info?: Uint8Array;
  /** Desired key length in bits. Defaults to 256. */
  keyLength?: number;
};

/**
 * Public key information returned from importPublicKeyPem.
 */
export type PublicKeyInfo = {
  /** Detected algorithm of the key. */
  algorithm: 'rsa:2048' | 'rsa:4096' | 'ec:secp256r1' | 'ec:secp384r1' | 'ec:secp521r1';
  /** Normalized PEM string. */
  pem: string;
};

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
   * Note: Callers should treat inputs and outputs as hex-encoded byte strings.
   * Implementations may normalize case, but callers MUST NOT rely on a specific case.
   */
  hmac: (key: string, content: string) => Promise<string>;

  randomBytes: (byteLength: number) => Promise<Uint8Array>;

  /** Compute the hex-encoded SHA hash of a UTF-16 encoded string. */
  sha256: (content: string) => Promise<string>;

  /**
   * Sign data with an asymmetric private key.
   * @param data - Data to sign
   * @param privateKeyPem - PEM-encoded private key (PKCS#8 format)
   * @param algorithm - Signing algorithm (RS256, ES256, ES384, ES512)
   */
  sign: (
    data: Uint8Array,
    privateKeyPem: string,
    algorithm: AsymmetricSigningAlgorithm
  ) => Promise<Uint8Array>;

  /**
   * Verify signature with an asymmetric public key.
   * @param data - Original data that was signed
   * @param signature - Signature to verify
   * @param publicKeyPem - PEM-encoded public key (SPKI format)
   * @param algorithm - Must match algorithm used for signing
   */
  verify: (
    data: Uint8Array,
    signature: Uint8Array,
    publicKeyPem: string,
    algorithm: AsymmetricSigningAlgorithm
  ) => Promise<boolean>;

  /**
   * Sign data with a symmetric key (HMAC-SHA256).
   * @param data - Data to sign
   * @param key - Raw key bytes (NOT hex-encoded like hmac())
   * @returns Signature bytes
   *
   * Note: Different from hmac() which uses hex encoding for TDF3 policy binding.
   * This method is for JWT HS256 signing with raw byte keys.
   */
  signSymmetric: (data: Uint8Array, key: Uint8Array) => Promise<Uint8Array>;

  /**
   * Verify symmetric signature (HMAC-SHA256).
   * @param data - Original data that was signed
   * @param signature - Signature to verify
   * @param key - Raw key bytes
   */
  verifySymmetric: (data: Uint8Array, signature: Uint8Array, key: Uint8Array) => Promise<boolean>;

  /**
   * Compute hash digest.
   * @param algorithm - Hash algorithm to use (SHA-256, SHA-384, SHA-512)
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
   * For certificates, jwaAlgorithm must be provided to correctly parse the key
   * (e.g., 'RS256', 'RS512', 'ES256', 'ES384', 'ES512'). For raw PEM keys,
   * the algorithm parameter is ignored.
   *
   * @param certOrPem - PEM-encoded public key or X.509 certificate
   * @param jwaAlgorithm - JWA algorithm for certificate parsing (required for certificates)
   * @returns PEM-encoded public key (SPKI format)
   * @throws Error if input is not valid PEM or certificate
   */
  extractPublicKeyPem: (certOrPem: string, jwaAlgorithm?: string) => Promise<string>;

  /**
   * Generate an EC key pair for ECDH key agreement or ECDSA signing.
   * @param curve - Elliptic curve to use (defaults to P-256)
   * @throws ConfigurationError if EC operations not supported
   */
  generateECKeyPair: (curve?: ECCurve) => Promise<PemKeyPair>;

  /**
   * Perform ECDH key agreement followed by HKDF key derivation.
   * Returns raw derived key bytes suitable for symmetric encryption.
   *
   * @param privateKeyPem - PEM-encoded EC private key
   * @param publicKeyPem - PEM-encoded EC public key of other party
   * @param hkdfParams - Parameters for HKDF derivation
   * @returns Raw derived key bytes
   * @throws ConfigurationError if EC operations not supported
   */
  deriveKeyFromECDH: (
    privateKeyPem: string,
    publicKeyPem: string,
    hkdfParams: HkdfParams
  ) => Promise<Uint8Array>;

  /**
   * Import and validate a PEM public key, returning algorithm info.
   *
   * @param pem - PEM-encoded public key or X.509 certificate
   * @returns Validated PEM and detected algorithm
   * @throws ConfigurationError if key format invalid or algorithm not supported
   */
  importPublicKeyPem: (pem: string) => Promise<PublicKeyInfo>;

  /**
   * Convert a JWK (JSON Web Key) to PEM format.
   * Supports both RSA and EC keys.
   *
   * @param jwk - JSON Web Key object
   * @returns PEM-encoded public key
   * @throws ConfigurationError if JWK format invalid
   */
  jwkToPem: (jwk: JsonWebKey) => Promise<string>;
};
