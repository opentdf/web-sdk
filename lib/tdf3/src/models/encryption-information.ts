import { keySplit } from '../utils/index.js';
import { base64, hex } from '../../../src/encodings/index.js';
import { Binary } from '../binary.js';
import { type SymmetricCipher } from '../ciphers/symmetric-cipher-base.js';
import { type KeyAccess, type KeyAccessObject } from './key-access.js';
import { type Policy } from './policy.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
} from '../crypto/declarations.js';
import { IntegrityAlgorithm } from '../tdf.js';

export type KeyInfo = {
  readonly unwrappedKeyBinary: Binary;
  readonly unwrappedKeyIvBinary: Binary;
};

export type Segment = {
  readonly hash: string;
  // If not present, segmentSizeDefault must be defined and used.
  readonly segmentSize?: number;
  // If not present, encryptedSegmentSizeDefault must be defined and used.??
  readonly encryptedSegmentSize?: number;
};

export type SplitType = 'split' | 'flat';

export type EncryptionInformation = {
  readonly type: SplitType;
  readonly keyAccess: KeyAccessObject[];
  readonly integrityInformation: {
    readonly rootSignature: {
      alg: IntegrityAlgorithm;
      sig: string;
    };
    segmentHashAlg?: IntegrityAlgorithm;
    segments: Segment[];
    segmentSizeDefault?: number;
    encryptedSegmentSizeDefault?: number;
  };
  readonly method: {
    readonly algorithm: string;
    isStreamable: boolean;
    readonly iv: string;
  };
  policy: string;
};

export class SplitKey {
  readonly cryptoService: CryptoService;
  keyAccess: KeyAccess[];

  constructor(public readonly cipher: SymmetricCipher) {
    this.cryptoService = cipher.cryptoService;
    this.keyAccess = [];
  }

  async generateKey(): Promise<KeyInfo> {
    const unwrappedKey = await this.cipher.generateKey();
    const unwrappedKeyBinary = Binary.fromString(hex.decode(unwrappedKey));
    const unwrappedKeyIvBinary = await this.generateIvBinary();
    return { unwrappedKeyBinary, unwrappedKeyIvBinary };
  }

  async encrypt(
    contentBinary: Binary,
    keyBinary: Binary,
    ivBinaryOptional?: Binary
  ): Promise<EncryptResult> {
    const ivBinary = ivBinaryOptional || (await this.generateIvBinary());
    return this.cipher.encrypt(contentBinary, keyBinary, ivBinary);
  }

  async decrypt(content: Uint8Array, keyBinary: Binary): Promise<DecryptResult> {
    return this.cipher.decrypt(content, keyBinary);
  }

  async getKeyAccessObjects(policy: Policy, keyInfo: KeyInfo): Promise<KeyAccessObject[]> {
    const splitIds = [...new Set(this.keyAccess.map(({ split }) => split))].sort();
    const unwrappedKeySplitBuffers = await keySplit(
      new Uint8Array(keyInfo.unwrappedKeyBinary.asByteArray()),
      splitIds.length,
      this.cryptoService
    );
    const splitsByName = Object.fromEntries(splitIds.map((split, index) => [split, unwrappedKeySplitBuffers[index]]));

    const keyAccessObjects = [];
    for (const item of this.keyAccess) {
      // use the key split to encrypt metadata for each key access object
      const unwrappedKeySplitBuffer = splitsByName[item.split];
      const unwrappedKeySplitBinary = Binary.fromArrayBuffer(unwrappedKeySplitBuffer.buffer);

      const metadata = item.metadata || '';
      const metadataStr = (
        typeof metadata === 'object'
          ? JSON.stringify(metadata)
          : typeof metadata === 'string'
          ? metadata
          : () => {
              throw new Error();
            }
      ) as string;

      const metadataBinary = Binary.fromArrayBuffer(new TextEncoder().encode(metadataStr));

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
      const keyAccessObject = await item.write(
        policy,
        unwrappedKeySplitBuffer,
        encryptedMetadataStr
      );
      keyAccessObjects.push(keyAccessObject);
    }

    return keyAccessObjects;
  }

  async generateIvBinary(): Promise<Binary> {
    const iv = await this.cipher.generateInitializationVector();
    return Binary.fromString(hex.decode(iv));
  }

  async write(policy: Policy, keyInfo: KeyInfo): Promise<EncryptionInformation> {
    const algorithm = this.cipher.name;
    if (!algorithm) {
      throw new Error('Uninitialized cipher type');
    }
    const keyAccessObjects = await this.getKeyAccessObjects(policy, keyInfo);

    // For now we're only concerned with a single (first) key access object
    const policyForManifest = base64.encode(JSON.stringify(policy));

    return {
      type: 'flat',
      keyAccess: keyAccessObjects,
      method: {
        algorithm,
        isStreamable: false,
        iv: base64.encode(keyInfo.unwrappedKeyIvBinary.asString()),
      },
      integrityInformation: {
        rootSignature: {
          alg: 'HS256',
          sig: '',
        },
        segmentHashAlg: 'GMAC',
        segments: [],
      },
      policy: policyForManifest,
    };
  }
}
