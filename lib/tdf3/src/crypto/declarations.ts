import { Binary } from '../binary';

export type EncryptResult = {
  /** Encrypted payload. */
  payload: Binary;
  /** Auth tag, if generated/ */
  authTag?: Binary;
};

export type DecryptResult = {
  payload: Binary;
};

export type PemKeyPair = {
  publicKey: string;
  privateKey: string;
};

/**
 * The minimum acceptable asymetric key size, currently 2^11.
 */
export const MIN_ASYMMETRIC_KEY_SIZE_BITS = 2048;

export type CryptoService = {
  /** Track which crypto implementation we are using */
  name: string;

  /** Default algorithm identifier. */
  method: string;

  /**
   * Try to decrypt content with the default or handed algorithm. Throws on
   * most failure, if auth tagging is implemented for example.
   */
  decrypt: (
    payload: Binary,
    key: Binary,
    iv: Binary,
    algorithm?: string,
    authTag?: Binary
  ) => Promise<DecryptResult>;

  decryptWithPrivateKey: (encryptedPayload: Binary, privateKey: string) => Promise<Binary>;

  /**
   * Encrypt content with the default or handed algorithm.
   */
  encrypt: (payload: Binary, key: Binary, iv: Binary, algorithm?: string) => Promise<EncryptResult>;

  encryptWithPublicKey: (payload: Binary, publicKey: string) => Promise<Binary>;

  /** Get length random bytes as a hex-encoded string. */
  generateInitializationVector: (length: number) => string;

  /** Get length random bytes as a hex-encoded string. */
  generateKey: (length: number) => string;

  /**
   * Generate an RSA key pair
   * @param size in bits, defaults to a reasonable size for the default method
   */
  generateKeyPair: (size?: number) => Promise<PemKeyPair>;

  /**
   * Create an HMAC SHA256 hash
   */
  hmac: (key: string, content: string) => Promise<string>;

  /** Compute the hex-encoded SHA hash of a UTF-16 encoded string. */
  sha256: (content: string) => Promise<string>;
};
