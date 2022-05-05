import { keySplit } from '../utils';
import { base64, hex } from '../encodings';
import { Binary } from '../binary';
import { SymmetricCipher } from '../ciphers/symmetric-cipher-base';
import { KeyAccess } from './key-access';
import { Policy } from './policy';

export type KeyInfo = {
  readonly unwrappedKeyBinary: Binary;
  readonly unwrappedKeyIvBinary: Binary;
};

export class SplitKey {
  readonly keyAccess: KeyAccess[];

  constructor(public readonly cipher: SymmetricCipher) {
    this.keyAccess = [];
  }

  async generateKey(): Promise<KeyInfo> {
    const unwrappedKey = this.cipher.generateKey();
    const unwrappedKeyBinary = Binary.fromString(hex.decode(unwrappedKey));
    const unwrappedKeyIvBinary = await this.generateIvBinary();
    return { unwrappedKeyBinary, unwrappedKeyIvBinary };
  }

  async encrypt(contentBinary: Binary, keyBinary: Binary, ivBinaryOptional?: Binary) {
    const ivBinary = ivBinaryOptional || (await this.generateIvBinary());
    return this.cipher.encrypt(contentBinary, keyBinary, ivBinary);
  }

  async decrypt(content: Binary, keyBinary: Binary) {
    return this.cipher.decrypt(content, keyBinary);
  }

  async getKeyAccessObjects(policy: Policy, keyInfo: KeyInfo) {
    const unwrappedKeySplitBuffers = keySplit(
      keyInfo.unwrappedKeyBinary.asBuffer(),
      this.keyAccess.length
    );

    const keyAccessObjects = [];
    for (let i = 0; i < this.keyAccess.length; i++) {
      // use the key split to encrypt metadata for each key access object
      const unwrappedKeySplitBuffer = unwrappedKeySplitBuffers[i];
      const unwrappedKeySplitBinary = Binary.fromBuffer(Buffer.from(unwrappedKeySplitBuffer));

      const metadata = this.keyAccess[i].metadata || '';
      const metadataStr = (
        typeof metadata === 'object'
          ? JSON.stringify(metadata)
          : typeof metadata === 'string'
          ? metadata
          : () => {
              throw new Error();
            }
      ) as string;

      const metadataBinary = Binary.fromString(metadataStr);

      const encryptedMetadataResult = await this.encrypt(
        metadataBinary,
        unwrappedKeySplitBinary,
        keyInfo.unwrappedKeyIvBinary
      );

      const encryptedMetadataOb = {
        ciphertext: base64.encode(encryptedMetadataResult.payload.asString()),
        iv: base64.encode(keyInfo.unwrappedKeyIvBinary.asString()),
      };

      const encryptedMetadataStr = JSON.stringify(encryptedMetadataOb);
      const keyAccessObject = await this.keyAccess[i].write(
        policy,
        unwrappedKeySplitBuffer,
        encryptedMetadataStr
      );
      keyAccessObjects.push(keyAccessObject);
    }

    return keyAccessObjects;
  }

  async generateIvBinary() {
    const iv = await this.cipher.generateInitializationVector();
    return Binary.fromString(hex.decode(iv));
  }

  async write(policy, keyInfo) {
    const keyAccessObjects = await this.getKeyAccessObjects(policy, keyInfo);

    // For now we're only concerned with a single (first) key access object
    const policyForManifest = base64.encode(JSON.stringify(policy));

    return {
      type: 'split',
      keyAccess: keyAccessObjects,
      method: {
        algorithm: this.cipher.name,
        isStreamable: false,
        iv: base64.encode(keyInfo.unwrappedKeyIvBinary.asString()),
      },
      integrityInformation: {
        rootSignature: {
          alg: 'HS256',
          sig: '',
        },
        segmentSizeDefault: '',
        segmentHashAlg: '',
        segments: [],
      },
      policy: policyForManifest,
    };
  }
}
