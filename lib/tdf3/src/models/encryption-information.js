import { keySplit } from '../utils';
import { base64, hex } from '../encodings';
import { Binary } from '../binary';

class EncryptionInformation {
  constructor() {
    this.keyAccess = [];
  }
}

class SplitKey extends EncryptionInformation {
  constructor(cipher) {
    super();
    this.cipher = cipher;
  }

  async generateKey() {
    const unwrappedKey = await this.cipher.generateKey();
    const unwrappedKeyBinary = Binary.fromString(hex.decode(unwrappedKey));
    const unwrappedKeyIvBinary = await this.generateIvBinary();
    return { unwrappedKeyBinary, unwrappedKeyIvBinary };
  }

  async encrypt(contentBinary, keyBinary, ivBinaryOptional) {
    const ivBinary = ivBinaryOptional || (await this.generateIvBinary());
    return this.cipher.encrypt(contentBinary, keyBinary, ivBinary);
  }

  async decrypt(content, keyBinary) {
    return this.cipher.decrypt(content, keyBinary);
  }

  async getKeyAccessObjects(policy, keyInfo) {
    const unwrappedKeySplitBuffers = keySplit(
      keyInfo.unwrappedKeyBinary.asBuffer(),
      this.keyAccess.length
    );

    const keyAccessObjects = [];
    for (let i = 0; i < this.keyAccess.length; i++) {
      // use the key split to encrypt metadata for each key access object
      const unwrappedKeySplitBuffer = unwrappedKeySplitBuffers[i];
      const unwrappedKeySplitBinary = Binary.fromBuffer(unwrappedKeySplitBuffer);

      const metadata = this.keyAccess[i].metadata || '';
      const metadataStr = typeof metadata === 'object' ? JSON.stringify(metadata) : metadata;

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
        encryptedMetadataStr,
        metadataStr
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

export default SplitKey;
