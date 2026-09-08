import { base64 } from '../../../src/encodings/index.js';
import { Binary } from '../binary.js';
import { type SymmetricCipher } from '../ciphers/symmetric-cipher-base.js';
import { type KeyAccess, type KeyAccessObject } from './key-access.js';
import { type Policy } from './policy.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type SymmetricKey,
} from '../crypto/declarations.js';
import { ROOT_INTEGRITY_ALGORITHM, SEGMENT_INTEGRITY_ALGORITHM } from '../tdf.js';
import { ConfigurationError } from '../../../src/errors.js';
import { toArrayBuffer } from '../utils/index.js';

export type KeyInfo = {
  readonly unwrappedKey: SymmetricKey;
  readonly unwrappedKeyIvBinary: Binary;
};

export type Segment = {
  readonly hash: string;
  // If not present, segmentSizeDefault must be defined and used.
  readonly segmentSize?: number;
  // If not present, encryptedSegmentSizeDefault must be defined and used.??
  readonly encryptedSegmentSize?: number;
};

export type SplitType = 'split';

export type EncryptionInformation = {
  readonly type: SplitType;
  readonly keyAccess: KeyAccessObject[];
  readonly integrityInformation: {
    readonly rootSignature: {
      /**
       * Algorithm declared by the file. Untrusted until validated on read;
       * only `HS256` is accepted (see `asRootIntegrityAlgorithm`). Typed as a
       * plain string because a hostile manifest may say anything.
       */
      alg: string;
      sig: string;
    };
    /** Untrusted until validated on read; `GMAC` and `HS256` are accepted. */
    segmentHashAlg?: string;
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
    // A random IV, used only by callers that go on to invoke `write` or
    // `getKeyAccessObjects` directly. On the `writeStream` path it is always
    // overridden with invocation zero of the stream's own counter, so that
    // metadata and payload share one fixed field, and this draw is discarded.
    const { ivLength } = this.cipher;
    if (!ivLength) {
      // Hard coded as part of the cipher object. This should not be reachable.
      throw new ConfigurationError('uninitialized cipher iv length');
    }
    const iv = await this.cryptoService.randomBytes(ivLength);
    return { unwrappedKey, unwrappedKeyIvBinary: Binary.fromArrayBuffer(toArrayBuffer(iv)) };
  }

  /**
   * @param ivBinary required. Declared optional only so that callers compiled
   * against an older release still typecheck; omitting it now throws rather
   * than falling back to a fresh random IV, because every IV the writer uses
   * must come from the stream's counter.
   */
  async encrypt(
    contentBinary: Binary,
    key: SymmetricKey,
    ivBinary?: Binary
  ): Promise<EncryptResult> {
    if (!ivBinary) {
      throw new ConfigurationError('encrypt requires an explicit iv');
    }
    return this.cipher.encrypt(contentBinary, key, ivBinary);
  }

  async decrypt(content: ArrayBuffer | Uint8Array, key: SymmetricKey): Promise<DecryptResult> {
    return this.cipher.decrypt(content, key);
  }

  /**
   * @param metadataIv IV for the encrypted metadata of every key access
   * object. Defaults to `keyInfo.unwrappedKeyIvBinary`; `writeStream` passes
   * invocation zero of the stream's IV counter so a key reused across two
   * TDFs still gets distinct metadata IVs.
   */
  async getKeyAccessObjects(
    policy: Policy,
    keyInfo: KeyInfo,
    metadataIv: Binary = keyInfo.unwrappedKeyIvBinary
  ): Promise<KeyAccessObject[]> {
    const splitIds = [...new Set(this.keyAccess.map(({ sid }) => sid || ''))].sort((a, b) =>
      a.localeCompare(b)
    );
    const unwrappedKeySplits = await this.cryptoService.splitSymmetricKey(
      keyInfo.unwrappedKey,
      splitIds.length
    );
    const splitsByName = splitIds.reduce<Record<string, SymmetricKey | undefined>>(
      (result, sid, index) => {
        result[sid] = unwrappedKeySplits[index];
        return result;
      },
      {}
    );

    const keyAccessObjects: KeyAccessObject[] = [];
    for (const item of this.keyAccess) {
      // use the key split to encrypt metadata for each key access object
      const unwrappedKeySplit = splitsByName[item.sid || ''];
      if (!unwrappedKeySplit) {
        throw new ConfigurationError(`Missing key split for sid [${item.sid || ''}]`);
      }

      const metadata = item.metadata || '';
      const metadataStr = (
        typeof metadata === 'object'
          ? JSON.stringify(metadata)
          : typeof metadata === 'string'
            ? metadata
            : () => {
                throw new ConfigurationError(
                  "KAO generation failure: metadata isn't a string or object"
                );
              }
      ) as string;

      const metadataBinary = Binary.fromArrayBuffer(
        toArrayBuffer(new TextEncoder().encode(metadataStr))
      );

      // Every key access object in one manifest shares this IV. That is safe
      // because each distinct `sid` gets its own split key, so a shared IV is
      // not nonce reuse. Two key access objects with the *same* `sid` do share
      // a key, and are safe only because they encrypt byte-identical metadata.
      // So: do not give same-`sid` key access objects differing metadata
      // without first giving each its own IV.
      const encryptedMetadataResult = await this.encrypt(
        metadataBinary,
        unwrappedKeySplit,
        metadataIv
      );

      const encryptedMetadataOb = {
        ciphertext: base64.encode(encryptedMetadataResult.payload.asString()),
        iv: base64.encode(metadataIv.asString()),
      };

      const encryptedMetadataStr = JSON.stringify(encryptedMetadataOb);
      const keyAccessObject = await item.write(policy, unwrappedKeySplit, encryptedMetadataStr);
      keyAccessObjects.push(keyAccessObject);
    }

    return keyAccessObjects;
  }

  /**
   * @deprecated Payload IVs now come from the stream's `GcmIvCounter`, not from
   * a fresh random draw. Retained so callers compiled against an older release
   * keep working; do not use its output as a payload IV.
   */
  async generateIvBinary(): Promise<Binary> {
    const { ivLength } = this.cipher;
    if (!ivLength) {
      // Hard coded as part of the cipher object. This should not be reachable.
      throw new ConfigurationError('uninitialized cipher iv length');
    }
    const iv = await this.cryptoService.randomBytes(ivLength);
    return Binary.fromArrayBuffer(toArrayBuffer(iv));
  }

  /** @param metadataIv see {@link getKeyAccessObjects}. */
  async write(
    policy: Policy,
    keyInfo: KeyInfo,
    metadataIv: Binary = keyInfo.unwrappedKeyIvBinary
  ): Promise<EncryptionInformation> {
    const algorithm = this.cipher?.name;
    if (!algorithm) {
      // Hard coded as part of the cipher object. This should not be reachable.
      throw new ConfigurationError('uninitialized cipher type');
    }
    const keyAccessObjects = await this.getKeyAccessObjects(policy, keyInfo, metadataIv);

    // For now we're only concerned with a single (first) key access object
    const policyForManifest = base64.encode(JSON.stringify(policy));

    return {
      type: 'split',
      keyAccess: keyAccessObjects,
      method: {
        algorithm,
        isStreamable: false,
        // Vestigial: payload segments carry their own IV prefix and each key
        // access object repeats this one alongside its ciphertext. Kept equal
        // to the metadata IV for schema compatibility.
        iv: base64.encode(metadataIv.asString()),
      },
      integrityInformation: {
        rootSignature: {
          // Placeholders; `writeStream` overwrites both once the payload has
          // been segmented and the aggregate hash is known.
          alg: ROOT_INTEGRITY_ALGORITHM,
          sig: '',
        },
        segmentHashAlg: SEGMENT_INTEGRITY_ALGORITHM,
        segments: [],
      },
      policy: policyForManifest,
    };
  }
}
