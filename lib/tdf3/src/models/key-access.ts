import { Binary } from '../binary.js';
import { base64, hex } from '../../../src/encodings/index.js';
import * as cryptoService from '../crypto/index.js';
import { Policy } from './policy.js';

export type KeyAccessType = 'remote' | 'wrapped';

export function isRemote(keyAccessJSON: KeyAccess | KeyAccessObject): boolean {
  return keyAccessJSON.type === 'remote';
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

export type KeyAccess = Wrapped;

export type KeyAccessObject = {
  sid?: string;
  type: KeyAccessType;
  url: string;
  kid?: string;
  protocol: 'kas';
  wrappedKey?: string;
  policyBinding?: {
    alg: string;
    hash: string;
  };
  encryptedMetadata?: string;
};
