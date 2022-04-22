import { Binary } from '../binary';
import { base64 } from '../encodings';
import { cryptoService } from '../crypto';

class KeyAccess {}

export class KeyUtil {
  static isRemote(keyAccessJSON) {
    return keyAccessJSON.type === 'remote';
  }
}

export class Wrapped extends KeyAccess {
  constructor(url, publicKey, metadata) {
    super();
    this.url = url;
    this.publicKey = publicKey;
    this.metadata = metadata;
    this.keyAccessObject = {};
  }

  async write(policy, keyBuffer, encryptedMetadataStr) {
    const policyStr = JSON.stringify(policy);
    const unwrappedKeyBinary = Binary.fromBuffer(keyBuffer);
    const wrappedKeyBinary = await cryptoService.encryptWithPublicKey(
      unwrappedKeyBinary,
      this.publicKey
    );

    const policyBinding = await cryptoService.hmac(
      keyBuffer.toString('hex'),
      base64.encode(policyStr)
    );

    this.keyAccessObject.type = 'wrapped';
    this.keyAccessObject.url = this.url;
    this.keyAccessObject.protocol = 'kas';
    this.keyAccessObject.wrappedKey = base64.encode(wrappedKeyBinary.asString());
    this.keyAccessObject.policyBinding = base64.encode(policyBinding);
    this.keyAccessObject.encryptedMetadata = base64.encode(encryptedMetadataStr);

    return this.keyAccessObject;
  }
}

export class Remote extends KeyAccess {
  constructor(url, publicKey, metadata) {
    super();
    this.url = url;
    this.publicKey = publicKey;
    this.keyAccessObject = {};
    this.wrappedKey = '';
    this.metadata = metadata;
    this.policyBinding = '';
  }

  async write(policy, keyBuffer, encryptedMetadataStr) {
    const policyStr = JSON.stringify(policy);
    const policyBinding = await cryptoService.hmac(
      keyBuffer.toString('hex'),
      base64.encode(policyStr)
    );
    const unwrappedKeyBinary = Binary.fromBuffer(keyBuffer);
    const wrappedKeyBinary = await cryptoService.encryptWithPublicKey(
      unwrappedKeyBinary,
      this.publicKey
    );

    // this.wrappedKey = wrappedKeyBinary.asBuffer().toString('hex');
    this.wrappedKey = base64.encode(wrappedKeyBinary.asString());

    this.keyAccessObject.type = 'remote';
    this.keyAccessObject.url = this.url;
    this.keyAccessObject.protocol = 'kas';
    this.keyAccessObject.wrappedKey = this.wrappedKey;
    this.keyAccessObject.encryptedMetadata = base64.encode(encryptedMetadataStr);
    this.keyAccessObject.policyBinding = base64.encode(policyBinding);

    return this.keyAccessObject;
  }
}

export default { KeyUtil, Remote, Wrapped };
