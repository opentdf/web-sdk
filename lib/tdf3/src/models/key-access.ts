import { base64, hex } from '../../../src/encodings/index.js';
import { generateKeyPair } from '../../../src/nanotdf-crypto/generateKeyPair.js';
import { generateRandomNumber } from '../../../src/nanotdf-crypto/generateRandomNumber.js';
import { keyAgreement } from '../../../src/nanotdf-crypto/keyAgreement.js';
import { pemPublicToCrypto } from '../../../src/nanotdf-crypto/pemPublicToCrypto.js';
import { cryptoPublicToPem } from '../../../src/utils.js';
import { Binary } from '../binary.js';
import * as cryptoService from '../crypto/index.js';
import { Policy } from './policy.js';

export type KeyAccessType = 'remote' | 'wrapped' | 'ec-wrapped';

export const schemaVersion = '1.0';

export function isRemote(keyAccessJSON: KeyAccess | KeyAccessObject): boolean {
  return keyAccessJSON.type === 'remote';
}

export class ECWrapped {
  readonly type = 'ec-wrapped';
  readonly ephemeralKeyPair;
  keyAccessObject?: KeyAccessObject;

  constructor(
    public readonly url: string,
    public readonly kid: string | undefined,
    public readonly publicKey: string,
    public readonly metadata: unknown,
    public readonly sid: string
  ) {
    this.ephemeralKeyPair = generateKeyPair();
  }

  async write(
    policy: Policy,
    dek: Uint8Array,
    encryptedMetadataStr: string
  ): Promise<KeyAccessObject> {
    const policyStr = JSON.stringify(policy);
    const [ek, clientPublicKey] = await Promise.all([
      this.ephemeralKeyPair,
      pemPublicToCrypto(this.publicKey),
    ]);
    const kek = await keyAgreement(ek.privateKey, clientPublicKey, {
      hkdfSalt: new TextEncoder().encode('salt'),
      hkdfHash: 'SHA-256',
    });
    const iv = generateRandomNumber(12);
    const cek = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, kek, dek);
    const entityWrappedKey = new Uint8Array(iv.length + cek.byteLength);
    entityWrappedKey.set(iv);
    entityWrappedKey.set(new Uint8Array(cek), iv.length);

    const policyBinding = await cryptoService.hmac(
      hex.encodeArrayBuffer(dek),
      base64.encode(policyStr)
    );

    const ephemeralPublicKeyPEM = await cryptoPublicToPem(ek.publicKey);
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
      ephemeralPublicKey: ephemeralPublicKeyPEM,
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
    public readonly sid: string
  ) {}

  async write(
    policy: Policy,
    keyBuffer: Uint8Array,
    encryptedMetadataStr: string
  ): Promise<KeyAccessObject> {
    const policyStr = JSON.stringify(policy);
    const unwrappedKeyBinary = Binary.fromArrayBuffer(keyBuffer.buffer);
    const wrappedKeyBinary = await cryptoService.encryptWithPublicKey(
      unwrappedKeyBinary,
      this.publicKey
    );

    const policyBinding = await cryptoService.hmac(
      hex.encodeArrayBuffer(keyBuffer),
      base64.encode(policyStr)
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
