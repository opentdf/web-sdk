import { base64, hex } from '../../src/encodings/index.js';
import { generateRandomNumber } from '../../src/nanotdf-crypto/generateRandomNumber.js';
import { keyAgreement } from '../../src/nanotdf-crypto/keyAgreement.js';
import { pemPublicToCrypto } from '../../src/nanotdf-crypto/pemPublicToCrypto.js';
import { cryptoPublicToPem } from '../../src/utils.js';
import { Binary } from './binary.js';
import * as cryptoService from './crypto/index.js';
import { ztdfSalt } from './crypto/salt.js';
import { type KeyAccessObject, type Policy } from './models/index.js';

export const schemaVersion = '1.0';

export class ECWrapped {
  readonly type = 'ec-wrapped';
  readonly ephemeralKeyPair: Promise<CryptoKeyPair>;
  keyAccessObject?: KeyAccessObject;

  constructor(
    public readonly url: string,
    public readonly kid: string | undefined,
    public readonly publicKey: string,
    public readonly metadata: unknown,
    public readonly sid?: string
  ) {
    this.ephemeralKeyPair = crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      ['deriveBits', 'deriveKey']
    );
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
      hkdfSalt: await ztdfSalt,
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
    public readonly sid?: string
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
