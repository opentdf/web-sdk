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
 * Used for import/export compatibility. Internal code should use KeyPair (opaque keys).
 */
export type PemKeyPair = {
  publicKey: string;
  privateKey: string;
};

/**
 * Key algorithm identifier combining key type and parameters.
 */
export type KeyAlgorithm =
  | 'rsa:2048'
  | 'rsa:4096'
  | 'ec:secp256r1'
  | 'ec:secp384r1'
  | 'ec:secp521r1';

/**
 * Options for key generation and import.
 */
export type KeyOptions = {
  /**
   * Key usage: 'encrypt' for RSA-OAEP, 'sign' for RSA/ECDSA signing, 'derive' for ECDH.
   * If not specified, defaults based on the generation method or key type.
   */
  usage?: 'encrypt' | 'sign' | 'derive';

  /**
   * Whether keys can be exported. Defaults to true.
   * HSM-backed implementations may force false for private keys.
   */
  extractable?: boolean;

  /**
   * Optional algorithm hint for import validation.
   * Helps disambiguate or validate imported keys.
   */
  algorithmHint?: KeyAlgorithm;
};

/**
 * Opaque public key - internal representation hidden.
 * Code outside CryptoService treats this as a token.
 *
 * Includes metadata for algorithm selection without needing CryptoService calls.
 */
export type PublicKey = {
  readonly _brand: 'PublicKey';
  /** Algorithm identifier (e.g., 'rsa:2048', 'ec:secp256r1') */
  readonly algorithm: KeyAlgorithm;
  /** RSA modulus bit length (only for RSA keys) */
  readonly modulusBits?: number;
  /** EC curve name (only for EC keys) */
  readonly curve?: ECCurve;
};

/**
 * Opaque private key - internal representation hidden.
 * Code outside CryptoService treats this as a token.
 *
 * Includes metadata for algorithm selection without needing CryptoService calls.
 */
export type PrivateKey = {
  readonly _brand: 'PrivateKey';
  /** Algorithm identifier (e.g., 'rsa:2048', 'ec:secp256r1') */
  readonly algorithm: KeyAlgorithm;
  /** RSA modulus bit length (only for RSA keys) */
  readonly modulusBits?: number;
  /** EC curve name (only for EC keys) */
  readonly curve?: ECCurve;
};

/**
 * Opaque key pair with matching algorithms.
 */
export type KeyPair = {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
};

/**
 * The minimum acceptable asymetric key size, currently 2^11.
 */
export const MIN_ASYMMETRIC_KEY_SIZE_BITS = 2048;

/**
 * Opaque symmetric key - internal representation hidden.
 * Code outside CryptoService treats this as a token.
 * Used for AES encryption/decryption.
 *
 * Includes metadata for key length without needing CryptoService calls.
 */
export type SymmetricKey = {
  readonly _brand: 'SymmetricKey';
  /** Key length in bits (e.g., 256 for AES-256) */
  readonly length: number;
};

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
 * Public key information returned from parsePublicKeyPem.
 */
export type PublicKeyInfo = {
  /** Detected algorithm of the key. */
  algorithm: 'rsa:2048' | 'rsa:4096' | 'ec:secp256r1' | 'ec:secp384r1' | 'ec:secp521r1';
  /** Normalized PEM string. */
  pem: string;
};

export type CryptoService = {
  /** Track which crypto implementation we are using */
  name: string;

  /** Default algorithm identifier. */
  method: AlgorithmUrn;

  /**
   * Try to decrypt content with the default or handed algorithm. Throws on
   * most failure, if auth tagging is implemented for example.
   */
  decrypt: (
    payload: Binary,
    key: SymmetricKey,
    iv: Binary,
    algorithm?: AlgorithmUrn,
    authTag?: Binary
  ) => Promise<DecryptResult>;

  decryptWithPrivateKey: (encryptedPayload: Binary, privateKey: PrivateKey) => Promise<Binary>;

  /**
   * Encrypt content with the default or handed algorithm.
   * Accepts Binary or SymmetricKey as payload (for key wrapping with symmetric keys).
   */
  encrypt: (
    payload: Binary | SymmetricKey,
    key: SymmetricKey,
    iv: Binary,
    algorithm?: AlgorithmUrn
  ) => Promise<EncryptResult>;

  /**
   * Encrypt with asymmetric public key (RSA-OAEP).
   * Accepts Binary or SymmetricKey for key wrapping.
   */
  encryptWithPublicKey: (payload: Binary | SymmetricKey, publicKey: PublicKey) => Promise<Binary>;

  /** Generate symmetric AES key (opaque, never hex string). */
  generateKey: (length?: number) => Promise<SymmetricKey>;

  /**
   * Generate an RSA key pair for encryption/decryption.
   * @param size in bits, defaults to a reasonable size for the default method
   * @returns Opaque key pair
   */
  generateKeyPair: (size?: number) => Promise<KeyPair>;

  /**
   * Generate an RSA key pair for signing/verification.
   * @returns Opaque key pair
   */
  generateSigningKeyPair: () => Promise<KeyPair>;

  /**
   * Compute HMAC-SHA256 of content using opaque symmetric key.
   * Used for TDF3 policy binding (integrity signature in manifest).
   *
   * This is separate from HS256 JWT signing (which uses signSymmetric/verifySymmetric).
   * The key is raw bytes (SymmetricKey), output is hex-encoded.
   *
   * @param key - Opaque symmetric key (raw bytes)
   * @param content - Content string to authenticate (typically base64-encoded policy)
   * @returns Hex-encoded HMAC result
   *
   * Note: Implementations may normalize case, but callers MUST NOT rely on a specific case.
   */
  hmac: (key: SymmetricKey, content: string) => Promise<string>;

  randomBytes: (byteLength: number) => Promise<Uint8Array>;

  /**
   * Sign data with an asymmetric private key.
   * @param data - Data to sign
   * @param privateKey - Opaque private key
   * @param algorithm - Signing algorithm (RS256, ES256, ES384, ES512)
   */
  sign: (
    data: Uint8Array,
    privateKey: PrivateKey,
    algorithm: AsymmetricSigningAlgorithm
  ) => Promise<Uint8Array>;

  /**
   * Verify signature with an asymmetric public key.
   * @param data - Original data that was signed
   * @param signature - Signature to verify
   * @param publicKey - Opaque public key
   * @param algorithm - Must match algorithm used for signing
   */
  verify: (
    data: Uint8Array,
    signature: Uint8Array,
    publicKey: PublicKey,
    algorithm: AsymmetricSigningAlgorithm
  ) => Promise<boolean>;

  /**
   * Sign data with a symmetric key (HMAC-SHA256).
   * @param data - Data to sign
   * @param key - Opaque symmetric key
   * @returns Signature bytes
   *
   * Note: Different from hmac() which returns hex-encoded string for TDF3 policy binding.
   * This method is for JWT HS256 signing and returns raw signature bytes.
   */
  signSymmetric: (data: Uint8Array, key: SymmetricKey) => Promise<Uint8Array>;

  /**
   * Verify symmetric signature (HMAC-SHA256).
   * @param data - Original data that was signed
   * @param signature - Signature to verify
   * @param key - Opaque symmetric key
   */
  verifySymmetric: (data: Uint8Array, signature: Uint8Array, key: SymmetricKey) => Promise<boolean>;

  /**
   * Compute hash digest.
   * @param algorithm - Hash algorithm to use (SHA-256, SHA-384, SHA-512)
   * @param data - Data to hash
   */
  digest: (algorithm: HashAlgorithm, data: Uint8Array) => Promise<Uint8Array>;

  /**
   * Generate an EC key pair for ECDH key agreement.
   * @param curve - Elliptic curve to use (defaults to P-256)
   * @throws ConfigurationError if EC operations not supported
   */
  generateECKeyPair: (curve?: ECCurve) => Promise<KeyPair>;

  /**
   * Perform ECDH key agreement followed by HKDF key derivation.
   * Returns opaque symmetric key suitable for symmetric encryption.
   *
   * @param privateKey - Opaque EC private key
   * @param publicKey - Opaque EC public key of other party
   * @param hkdfParams - Parameters for HKDF derivation
   * @returns Opaque symmetric key
   * @throws ConfigurationError if EC operations not supported
   */
  deriveKeyFromECDH: (
    privateKey: PrivateKey,
    publicKey: PublicKey,
    hkdfParams: HkdfParams
  ) => Promise<SymmetricKey>;

  // === Key Import (PEM → opaque) ===

  /**
   * Import a PEM public key as an opaque key.
   * @param pem - PEM-encoded public key
   * @param options - Import options (usage required for RSA keys to disambiguate encrypt vs sign)
   * @returns Opaque public key with metadata
   */
  importPublicKey: (pem: string, options: KeyOptions) => Promise<PublicKey>;

  /**
   * Import a PEM private key as an opaque key.
   * @param pem - PEM-encoded private key
   * @param options - Import options (usage required for RSA keys to disambiguate encrypt vs sign)
   * @returns Opaque private key with metadata
   */
  importPrivateKey: (pem: string, options: KeyOptions) => Promise<PrivateKey>;

  /**
   * Import a PEM key pair as opaque keys.
   * @param pem - PEM key pair
   * @param options - Import options (usage required for RSA keys to disambiguate encrypt vs sign)
   * @returns Opaque key pair with metadata
   */
  importKeyPair: (pem: PemKeyPair, options: KeyOptions) => Promise<KeyPair>;

  // === Key Export (opaque → PEM/JWK) ===

  /**
   * Export an opaque public key to PEM format.
   * @param key - Opaque public key
   * @returns PEM-encoded public key (SPKI format)
   */
  exportPublicKeyPem: (key: PublicKey) => Promise<string>;

  /**
   * OPTIONAL -- ONLY USE FOR TESTING/DEVELOPMENT. Private keys should NOT be exportable in secure environments.
   * Export an opaque private key to PEM format.
   * @param key - Opaque private key
   * @returns PEM-encoded private key (PKCS8 format)
   */
  exportPrivateKeyPem?: (key: PrivateKey) => Promise<string>;
  /**
   * Export an opaque public key to JWK format.
   * @param key - Opaque public key
   * @returns JWK representation
   */
  exportPublicKeyJwk: (key: PublicKey) => Promise<JsonWebKey>;

  // === Symmetric Key Operations ===

  /**
   * Import raw key bytes as an opaque symmetric key.
   * Used for external keys (e.g., unwrapped from KAS).
   * @param keyBytes - Raw key bytes
   * @returns Opaque symmetric key
   */
  importSymmetricKey: (keyBytes: Uint8Array) => Promise<SymmetricKey>;

  /**
   * Split a symmetric key into N shares using XOR secret sharing.
   *
   * DefaultCryptoService: Uses keySplit() utility (extracts bytes internally)
   * HSM implementations: Must use native splitting OR throw ConfigurationError
   *
   * @param key - Symmetric key to split
   * @param numShares - Number of shares to create
   * @returns Array of opaque key shares
   * @throws ConfigurationError if not supported by the implementation
   *
   * Note: Multi-KAS may not be available in all secure environments (single KAS only)
   */
  splitSymmetricKey: (key: SymmetricKey, numShares: number) => Promise<SymmetricKey[]>;

  /**
   * Merge symmetric key shares back into the original key using XOR.
   *
   * @param shares - Array of key shares (from splitSymmetricKey)
   * @returns Merged symmetric key
   * @throws ConfigurationError if not supported by the implementation
   */
  mergeSymmetricKeys: (shares: SymmetricKey[]) => Promise<SymmetricKey>;
};
