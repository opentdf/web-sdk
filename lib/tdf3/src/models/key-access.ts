import { base64, hex } from '../../../src/encodings/index.js';
import { Binary } from '../binary.js';
import type { CryptoService, KeyPair, SymmetricKey } from '../crypto/declarations.js';
import { getZtdfSalt } from '../crypto/salt.js';
import { Algorithms } from '../ciphers/index.js';
import { Policy } from './policy.js';

export type KeyAccessType = 'remote' | 'wrapped' | 'ec-wrapped';

export const schemaVersion = '1.0';

export class ECWrapped {
  readonly type = 'ec-wrapped';
  readonly ephemeralKeyPair: Promise<KeyPair>;
  keyAccessObject?: KeyAccessObject;

  constructor(
    public readonly url: string,
    public readonly kid: string | undefined,
    public readonly publicKey: string,
    public readonly metadata: unknown,
    public readonly cryptoService: CryptoService,
    public readonly sid?: string
  ) {
    // Generate EC key pair using CryptoService - returns opaque keys
    this.ephemeralKeyPair = this.cryptoService.generateECKeyPair('P-256');
  }

  async write(
    policy: Policy,
    dek: SymmetricKey,
    encryptedMetadataStr: string
  ): Promise<KeyAccessObject> {
    const policyStr = JSON.stringify(policy);
    const ek = await this.ephemeralKeyPair;

    // Import KAS public key from PEM
    const kasPublicKey = await this.cryptoService.importPublicKey(this.publicKey, {
      usage: 'derive',
    });

    // Derive encryption key using ECDH + HKDF via CryptoService
    const derivedKey = await this.cryptoService.deriveKeyFromECDH(ek.privateKey, kasPublicKey, {
      hash: 'SHA-256',
      salt: await getZtdfSalt(this.cryptoService),
    });

    // Generate random IV
    const iv = await this.cryptoService.randomBytes(12);

    // Encrypt DEK using derived key with AES-GCM
    // Payload is SymmetricKey (the DEK), key is SymmetricKey (derived from ECDH)
    const encryptResult = await this.cryptoService.encrypt(
      dek,
      derivedKey,
      Binary.fromArrayBuffer(iv.buffer),
      Algorithms.AES_256_GCM
    );

    // Combine IV, ciphertext, and authTag to form the wrapped key.
    const ciphertext = new Uint8Array(encryptResult.payload.asArrayBuffer());
    const authTag = encryptResult.authTag
      ? new Uint8Array(encryptResult.authTag.asArrayBuffer())
      : new Uint8Array(0);
    const entityWrappedKey = new Uint8Array(iv.length + ciphertext.length + authTag.length);
    entityWrappedKey.set(iv);
    entityWrappedKey.set(ciphertext, iv.length);
    entityWrappedKey.set(authTag, iv.length + ciphertext.length);

    const policyBinding = hex.encodeArrayBuffer(
      (await this.cryptoService.hmac(new TextEncoder().encode(base64.encode(policyStr)), dek)).buffer
    );

    // Export ephemeral public key to PEM for manifest
    const ephemeralPublicKeyPem = await this.cryptoService.exportPublicKeyPem(ek.publicKey);

    const kao: KeyAccessObject = {
      type: 'ec-wrapped',
      url: this.url,
      protocol: 'kas',
      wrappedKey: base64.encodeArrayBuffer(entityWrappedKey),
      encryptedMetadata: base64.encode(encryptedMetadataStr),
      policyBinding: {
        alg: 'HS256',
        hash: base64.encode(policyBinding),
      },
      schemaVersion,
      ephemeralPublicKey: ephemeralPublicKeyPem,
    };
    if (this.kid) {
      kao.kid = this.kid;
    }
    if (this.sid?.length) {
      kao.sid = this.sid;
    }
    this.keyAccessObject = kao;
    return kao;
  }
}

export class Wrapped {
  readonly type = 'wrapped';
  keyAccessObject?: KeyAccessObject;

  constructor(
    public readonly url: string,
    public readonly kid: string | undefined,
    public readonly publicKey: string,
    public readonly metadata: unknown,
    public readonly cryptoService: CryptoService,
    public readonly sid?: string
  ) {}

  async write(
    policy: Policy,
    key: SymmetricKey,
    encryptedMetadataStr: string
  ): Promise<KeyAccessObject> {
    const policyStr = JSON.stringify(policy);
    // Import KAS public key from PEM
    const kasPublicKey = await this.cryptoService.importPublicKey(this.publicKey, {
      usage: 'encrypt',
    });
    const wrappedKeyBinary = await this.cryptoService.encryptWithPublicKey(key, kasPublicKey);

    const policyBinding = hex.encodeArrayBuffer(
      (await this.cryptoService.hmac(new TextEncoder().encode(base64.encode(policyStr)), key)).buffer
    );

    this.keyAccessObject = {
      type: 'wrapped',
      url: this.url,
      protocol: 'kas',
      wrappedKey: base64.encode(wrappedKeyBinary.asString()),
      encryptedMetadata: base64.encode(encryptedMetadataStr),
      policyBinding: {
        alg: 'HS256',
        hash: base64.encode(policyBinding),
      },
      schemaVersion,
    };
    if (this.kid) {
      this.keyAccessObject.kid = this.kid;
    }
    if (this.sid?.length) {
      this.keyAccessObject.sid = this.sid;
    }

    return this.keyAccessObject;
  }
}

export type KeyAccess = ECWrapped | Wrapped;

/**
 * A KeyAccess object stores all information about how an object key OR one key split is stored.
 */
export type KeyAccessObject = {
  /**
   * Specifies how the key is stored. Possible Values:
   * **wrapped**: The wrapped key is stored as part of the manifest.
   * **remote**: [Unsupported] The wrapped key (see below) is stored remotely and is thus not part of the final TDF manifest.
   */
  type: KeyAccessType;

  /**
   * A key split (or share) identifier.
   * To allow sharing a key across several access domains,
   * the KAO supports a 'Split Identifier'.
   * To reconstruct such a key when encryptionInformation type is 'split',
   * use the xor operation to combine one of each separate sid.
   */
  sid?: string;

  /**
   * A locator for a Key Access service capable of granting access to the wrapped key.
   */
  url: string;

  /**
   * Additional information for the Key Access service to identify how to unwrap the key.
   */
  kid?: string;

  /**
   * The protocol used to access the key.
   */
  protocol: 'kas';

  /**
   * The symmetric key used to encrypt the payload.
   * It is encrypted using the public key of the KAS,
   * then base64 encoded.
   */
  wrappedKey?: string;

  /**
   * An object that contains a keyed hash that will provide cryptographic integrity on the policy object,
   * such that it cannot be modified or copied to another TDF
   * without invalidating the binding.
   * Specifically, you would have to have access to the key in order to overwrite the policy.
   */
  policyBinding?: {
    alg: string;
    hash: string;
  };

  /**
   * Metadata associated with the TDF and the request.
   * The contents of the metadata are freeform,
   * and are used to pass information from the client to the KAS.
   * The metadata stored here should not be used for primary access decisions.
   */
  encryptedMetadata?: string;

  /**
   * Version information for the KAO format.
   */
  schemaVersion?: string;

  /**
   * PEM encoded ephemeral public key, if wrapped with a KAS EC key.
   */
  ephemeralPublicKey?: string;
};
