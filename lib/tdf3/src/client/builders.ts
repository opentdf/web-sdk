import { validateAttribute, validateAttributeObject } from './validation.js';
import { AttributeObject, KeyInfo, Policy } from '../models/index.js';
import { type Metadata } from '../tdf.js';
import { Binary } from '../binary.js';

import { ConfigurationError } from '../../../src/errors.js';
import { PemKeyPair } from '../crypto/declarations.js';
import { DecoratedReadableStream } from './DecoratedReadableStream.js';
import { type Chunker } from '../../../src/seekable.js';
import { AssertionConfig, AssertionVerificationKeys } from '../assertions.js';
import { Value } from '../../../src/policy/attributes.js';
import { OriginAllowList } from '../../../src/access.js';

export const DEFAULT_SEGMENT_SIZE: number = 1024 * 1024;
export type Scope = {
  dissem?: string[];
  policyId?: string;
  policyObject?: Policy;
  attributes?: (string | AttributeObject)[];
  attributeValues?: Value[];
};

export type EncryptKeyMiddleware = (...args: unknown[]) => Promise<{
  keyForEncryption: KeyInfo;
  keyForManifest: KeyInfo;
}>;

export type EncryptStreamMiddleware = (
  stream: DecoratedReadableStream
) => Promise<DecoratedReadableStream>;

export type SplitStep = {
  kas: string;
  sid?: string;
};

export type EncryptParams = {
  byteLimit?: number;
  source: ReadableStream<Uint8Array>;
  opts?: { keypair: PemKeyPair };
  autoconfigure?: boolean;
  scope?: Scope;
  metadata?: Metadata;
  keypair?: CryptoKeyPair;
  windowSize?: number;
  getPolicyId?: () => Scope['policyId'];
  mimeType?: string;
  payloadKey?: Binary;
  keyMiddleware?: EncryptKeyMiddleware;
  splitPlan?: SplitStep[];
  streamMiddleware?: EncryptStreamMiddleware;
  assertionConfigs?: AssertionConfig[];
  defaultKASEndpoint?: string;

  // Unsupported
  asHtml?: boolean;
  // Unsupported
  offline?: boolean;
};

// 'Readonly<EncryptParams>': scope, metadata, offline, windowSize, asHtml
// deep copy is expensive, could be faster is Immer used, but to keep SDK work
// stable we can just make this object readonly
function freeze<Type>(obj: Type): Readonly<Type> {
  return Object.freeze<Type>(obj);
}

/**
 * A builder capable of constructing the necessary parameters object for a
 * {@link Client#encrypt|encrypt} operation. Must be built before use via the {@link EncryptParamsBuilder#build|build()} function.
 */
class EncryptParamsBuilder {
  _params: Partial<EncryptParams>;

  constructor(
    params: Partial<EncryptParams> = {
      scope: {
        dissem: [],
        attributes: [],
      },
      keypair: undefined,
      windowSize: DEFAULT_SEGMENT_SIZE,
      assertionConfigs: [],
    }
  ) {
    this._params = { ...params };
  }

  getStreamSource(): EncryptParams['source'] | undefined {
    return this._params.source;
  }

  /**
   * Specify the content to encrypt, in stream form.
   * @param {Readable} readStream - a Readable Stream to encrypt.
   */
  setStreamSource(readStream: ReadableStream<Uint8Array>) {
    this._params.source = readStream;
  }

  /**
   * Specify the content to encrypt, in stream form. Returns this object for method chaining.
   * @param {Readable} readStream - a Readable Stream to encrypt.
   * @return {EncryptParamsBuilder} - this object.
   */
  withStreamSource(readStream: ReadableStream<Uint8Array>): EncryptParamsBuilder {
    if (!readStream?.getReader) {
      throw new ConfigurationError(
        `Source must be a WebReadableStream. Run node streams through stream.Readable.toWeb()`
      );
    }

    this.setStreamSource(readStream);
    return this;
  }

  /**
   * Specify the content to encrypt, in string form.
   * @param {string} string - a string to encrypt.
   */
  setStringSource(string: string) {
    const stream = new ReadableStream({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode(string));
        controller.close();
      },
    });
    this.setStreamSource(stream);
  }

  /**
   * Specify the content to encrypt, in string form. Returns this object for method chaining.
   * @param {string} string - a string to encrypt.
   * @return {EncryptParamsBuilder} - this object.
   */
  withStringSource(string: string): EncryptParamsBuilder {
    this.setStringSource(string);
    return this;
  }

  /**
   * If set, the encrypt method will use the KAS Grants from the
   * policy service to configure the Key Access Object array, instead
   * of the client object's default `kasEndpoint`.
   */
  withAutoconfigure(enabled: boolean = true) {
    this._params.autoconfigure = enabled;
    return this;
  }

  /**
   * Specify the content to encrypt, in buffer form.
   * @param buf to encrypt.
   */
  setBufferSource(buf: ArrayBuffer) {
    const stream = new ReadableStream({
      pull(controller) {
        controller.enqueue(buf);
        controller.close();
      },
    });
    this.setStreamSource(stream);
  }

  /**
   * Specify the content to encrypt, in buffer form. Returns this object for method chaining.
   * @param buf - a buffer to encrypt
   */
  withBufferSource(buf: ArrayBuffer): this {
    this.setBufferSource(buf);
    return this;
  }

  /**
   * Specify the content to encrypt using an ArrayBuffer reference, which must have already
   * loaded the file content. Using the below linked example, e.target.result is the ArrayBuffer.
   * <br/><br/>
   * Example: https://developer.mozilla.org/en-US/docs/Web/API/FileReader/onload
   *
   * @param {ArrayBuffer} arraybuffer - the array buffer containing the file to encrypt.
   * @return {EncryptParamsBuilder} - this object
   */
  setArrayBufferSource(arraybuffer: ArrayBuffer) {
    this.setBufferSource(arraybuffer);
  }

  /**
   * Specify the content to encrypt using an ArrayBuffer reference. Returns this object for method chaining.
   *
   * @param  {ArrayBuffer} arraybuffer - the ArrayBuffer used to load file content from a browser
   * @return {EncryptParamsBuilder} - this object.
   */
  withArrayBufferSource(arraybuffer: ArrayBuffer): EncryptParamsBuilder {
    this.setArrayBufferSource(arraybuffer);
    return this;
  }

  getAttributes(): Scope['attributes'] {
    return this._params?.scope?.attributes || [];
  }

  /**
   * @param attributes URIs of the form `<authority namespace>/attr/<name>/value/<value>`
   */
  setAttributes(attributes?: (string | AttributeObject)[]) {
    if (!attributes) {
      if (this._params.scope) {
        delete this._params.scope.attributes;
        if (!Object.keys(this._params.scope).length) {
          delete this._params.scope;
        }
      }
      return;
    }
    attributes.forEach((a) => {
      if (typeof a === 'string') {
        validateAttribute(a);
      } else {
        validateAttributeObject(a);
      }
    });
    if (this._params.scope) {
      this._params.scope.attributes = attributes;
    } else {
      this._params.scope = { attributes, dissem: [] };
    }
  }

  /**
   * @param {Object} attributes
   * @param {String} attributes.attribute URI of the form `<authority namespace>/attr/<name>/value/<value>`
   * @returns {EncryptParamsBuilder} with attributes set
   */
  withAttributes(attributes: Scope['attributes']): EncryptParamsBuilder {
    this.setAttributes(attributes);
    return this;
  }

  /**
   * Get the users configured to access (decrypt) the encrypted data.
   * @return {array} - array of users (e.g., email addresses).
   */
  getUsersWithAccess(): Scope['dissem'] {
    return this._params?.scope?.dissem || [];
  }

  /**
   * Specify the full list of users configured to access (decrypt) the encrypted data.
   * @param {array} users - varargs or array of users (e.g., email addresses).
   */
  setUsersWithAccess(users: string[]) {
    if (this._params.scope) {
      this._params.scope.dissem = users;
    } else {
      this._params.scope = { attributes: [], dissem: users };
    }
  }

  /**
   * Specify the full list of users configured to access (decrypt) the encrypted data. Returns this object for method chaining.
   * <br/><br/>
   * @param {array} users - varargs or array of users (e.g., email addresses).
   * @return {EncryptParamsBuilder} - this object.
   */
  withUsersWithAccess(users: string[]): EncryptParamsBuilder {
    this.setUsersWithAccess(users);
    return this;
  }

  /**
   * Get the metadata (arbitrary key-value pairs) to be associated with the encrypted blob.
   * </br></br>
   * This metadata is encrypted alongside the content and stored in the TDF ciphertext.
   * @return {object} - object containing metadata as key-value pairs.
   */
  getMetadata(): EncryptParams['metadata'] {
    return this._params.metadata as Metadata;
  }

  /**
   * Specify the metadata (arbitrary key-value pairs) to be associated with the encrypted blob.
   * </br></br>
   * This metadata is encrypted alongside the content and stored in the TDF ciphertext.
   * @param {object} metadata - object containing metadata as key-value pairs.
   */
  setMetadata(metadata: EncryptParams['metadata']) {
    this._params.metadata = metadata;
  }

  /**
   * Specify the metadata (arbitrary key-value pairs) to be associated with the encrypted blob.
   * Returns this object for method chaining.
   * </br></br>
   * This metadata is encrypted alongside the content and stored in the TDF ciphertext.
   * @param {object} metadata - object containing metadata as key-value pairs.
   * @return {EncryptParamsBuilder} - this object.
   */
  withMetadata(metadata: EncryptParams['metadata']) {
    this.setMetadata(metadata);
    return this;
  }

  getPolicyId(): string | undefined {
    return this._params.scope?.policyId;
  }

  setPolicyId(policyId: string) {
    if (this._params.scope) {
      this._params.scope.policyId = policyId;
    } else {
      this._params.scope = { attributes: [], dissem: [], policyId };
    }
  }

  withPolicyId(policyId: string): EncryptParamsBuilder {
    this.setPolicyId(policyId);
    return this;
  }

  isOnline(): boolean {
    return !this._params.offline;
  }

  setOnline() {
    this._params.offline = false;
  }

  setOffline() {
    this._params.offline = true;
  }

  withOffline(): EncryptParamsBuilder {
    this.setOffline();
    return this;
  }

  withOnline(): EncryptParamsBuilder {
    this.setOnline();
    return this;
  }

  /**
   * Get the size of the sliding window to use when writing out the encrypted ciphertext.
   * Used to bound the memory used by the client for large files.
   * <br/><br/>
   * This window will match the "segment size" defined in the
   * <a href="https://github.com/virtru/tdf3-spec">TDF spec</a>, so a larger window
   * will result in more compact ciphertext.
   * @return {number} The sliding window size, in bytes (1MB by default).
   */
  getStreamWindowSize(): number | undefined {
    return this._params.windowSize;
  }

  /**
   * Set the size of the sliding window to use when writing out the encrypted ciphertext.
   * Used to bound the memory used by the client for large files.
   * <br/><br/>
   * This window will match the "segment size" defined in the
   * <a href="https://github.com/virtru/tdf3-spec">TDF spec</a>, so a larger window
   * will result in more compact ciphertext.
   * @param {number} numBytes sliding window size, in bytes (1MB by default).
   */
  setStreamWindowSize(numBytes: number) {
    if (numBytes <= 0) {
      throw new ConfigurationError('Stream window size must be positive');
    }
    this._params.windowSize = numBytes;
  }

  /**
   * Set the size of the sliding window to use when writing out the encrypted ciphertext.
   * Used to bound the memory used by the client for large files. Returns this object for method chaining.
   * <br/><br/>
   * This window will match the "segment size" defined in the
   * <a href="https://github.com/virtru/tdf3-spec">TDF spec</a>, so a larger window
   * will result in more compact ciphertext.
   * @param {number} numBytes sliding window size, in bytes (1MB by default).
   * @return {EncryptParamsBuilder} - this object.
   */
  withStreamWindowSize(numBytes: number): EncryptParamsBuilder {
    this.setStreamWindowSize(numBytes);
    return this;
  }

  /**
   * @deprecated This feature is not supported
   */
  hasHtmlFormat(): boolean {
    return false;
  }

  /**
   * @deprecated This feature is not supported
   */
  setHtmlFormat() {
    throw new ConfigurationError('HTML format is not supported');
  }

  /**
   * @deprecated This feature is not supported
   */
  withHtmlFormat(): EncryptParamsBuilder {
    throw new ConfigurationError('HTML format is not supported');
  }

  /**
   * Whether the encrypted data should be formatted using zip. This is more space efficient than html,
   * but authorized users must leverage the Virtru SDK to decrypt.
   * <br/><br/>
   * This is disabled by default (html is enabled by default).
   * @return {boolean} true if the encrypted data will be in zip format.
   */
  hasZipFormat(): boolean {
    return !this._params.asHtml;
  }

  /**
   * Whether the encrypted data should be formatted using zip. This is more space efficient than html,
   * but authorized users must leverage the Virtru SDK to decrypt.
   * <br/><br/>
   * This is disabled by default (html is enabled by default).
   */
  setZipFormat() {
    this._params.asHtml = false;
  }

  /**
   * Whether the encrypted data should be formatted using zip. This is more space efficient than html,
   * but authorized users must leverage the Virtru SDK to decrypt. Returns this object for method chaining.
   * <br/><br/>
   * This is disabled by default (html is enabled by default).
   * @return {EncryptParamsBuilder} - this object.
   */
  withZipFormat(): EncryptParamsBuilder {
    this.setZipFormat();
    return this;
  }

  /**
   * Gets the (consumer provided) mime type of the file to be protected
   */
  getMimeType(): string | undefined {
    return this._params.mimeType;
  }

  /**
   * Sets the mime type of the underlying file.
   * @param {string} mimeType - the content type string to be applied during decrypt
   * @return {EncryptParamsBuilder} - this object.
   */
  setMimeType(mimeType: string) {
    this._params.mimeType = mimeType;
  }

  /**
   * Sets the mime type of the underlying file.
   * @param {string} mimeType - the content type string to be applied during decrypt
   * @return {EncryptParamsBuilder} - this object.
   */
  withMimeType(mimeType: string): EncryptParamsBuilder {
    this.setMimeType(mimeType);
    return this;
  }

  _deepCopy(_params: EncryptParams) {
    return freeze({ ..._params, getPolicyId: () => _params.scope?.policyId });
  }

  /**
   * Generate a parameters object in the form expected by <code>{@link EncryptParamsBuilder#build|build()}</code>.
   * <br/><br/>
   * Creates a deep copy to prevent tricky call-by-reference and async execution bugs.
   */
  build(): Readonly<EncryptParams> {
    return this._deepCopy(this._params as EncryptParams);
  }

  /**
   * Sets the assertion configurations for the encryption parameters.
   *
   * @param {AssertionConfig[]} assertionConfigs - An array of assertion configurations to be set.
   * @returns {EncryptParamsBuilder} The current instance of the EncryptParamsBuilder for method chaining.
   */
  withAssertions(assertionConfigs: AssertionConfig[]): EncryptParamsBuilder {
    this._params.assertionConfigs = assertionConfigs;
    return this;
  }
}

export type DecryptKeyMiddleware = (key: Binary) => Promise<Binary>;

export type DecryptStreamMiddleware = (
  stream: DecoratedReadableStream
) => Promise<DecoratedReadableStream>;

export type DecryptSource =
  | { type: 'buffer'; location: Uint8Array }
  | { type: 'chunker'; location: Chunker }
  | { type: 'remote'; location: string }
  | { type: 'stream'; location: ReadableStream<Uint8Array> }
  | { type: 'file-browser'; location: Blob };

export type DecryptParams = {
  source: DecryptSource;
  allowList?: OriginAllowList;
  keyMiddleware?: DecryptKeyMiddleware;
  streamMiddleware?: DecryptStreamMiddleware;
  assertionVerificationKeys?: AssertionVerificationKeys;
  concurrencyLimit?: number;
  noVerifyAssertions?: boolean;
};

/**
 * A builder capable of constructing the necessary parameters object for a
 * <code>{@link Client#decrypt|decrypt}</code> operation. Must be built using the <code>{@link DecryptParamsBuilder#build|build()}</code> function.
 * <br/><br/>
 * Decrypt does not currently allow for setting a {@link EncryptParamsBuilder#getStreamWindowSize|stream window size}. Support for this configuration will be added in the near future.
 * <br/><br/>
 * Example usage:
 * <pre>
 // Configure the parameters to decrypt a local file.
 const decryptParams = new Virtru.DecryptParamsBuilder()
 .withFileSource("encrypted.html")
 .build();

 // Run the decrypt and write the result to stdout (node-style).
 (await client.decrypt(decryptParams)).pipe(process.stdout);
 </pre>
 */
class DecryptParamsBuilder {
  _params: Partial<DecryptParams>;

  constructor(to_copy: Partial<DecryptParams> = {}) {
    this._params = {
      ...to_copy,
    };
  }

  getStreamSource(): DecryptSource | undefined {
    return this._params.source;
  }

  /**
   * Set the TDF ciphertext to decrypt, in buffer form.
   * @param buffer to decrypt.
   */
  setBufferSource(buffer: Uint8Array) {
    this._params.source = { type: 'buffer', location: buffer };
  }

  /**
   * Set the TDF ciphertext to decrypt, in buffer form. Returns this object for method chaining.
   * @param buffer to decrypt.
   */
  withBufferSource(buffer: Uint8Array): this {
    this.setBufferSource(buffer);
    return this;
  }

  /**
   * Specify the TDF ciphertext to decrypt, from an http(s) URL.
   * TODO: add support for TDF.html encoding
   * @param {string} url - a url pointing to a tdf3 file
   */
  setUrlSource(url: string) {
    if (!/^https?/.exec(url)) {
      throw new ConfigurationError(`stream source must be a web url, not [${url}]`);
    }
    this._params.source = { type: 'remote', location: url };
  }

  /**
   * Specify the TDF ciphertext to decrypt, as a URL.
   * @param {string} url - a tdf3 remote URL.
   * @return {DecryptParamsBuilder} - this object.
   */
  withUrlSource(url: string): this {
    this.setUrlSource(url);
    return this;
  }

  /**
   * Specify the TDF ciphertext to decrypt, in stream form.
   * @param {Readable} stream - a Readable stream to decrypt.
   */
  setStreamSource(stream: ReadableStream<Uint8Array>) {
    this._params.source = { type: 'stream', location: stream };
  }

  /**
   * Specify the TDF ciphertext to decrypt, in stream form. Returns this object for method chaining.
   * @param stream to decrypt.
   */
  withStreamSource(stream: ReadableStream<Uint8Array>): this {
    if (!stream?.getReader) {
      throw new ConfigurationError(
        `Source must be a WebReadableStream. Run node streams through stream.Readable.toWeb()`
      );
    }

    this.setStreamSource(stream);
    return this;
  }

  /**
   * Specify the TDF ciphertext to decrypt, in string form.
   * @param {string} string - a string to decrypt.
   */
  setStringSource(string: string) {
    this.setBufferSource(new TextEncoder().encode(string));
  }

  /**
   * Specify the TDF ciphertext to decrypt, in string form. Returns this object for method chaining.
   * @param {string} string - a string to decrypt.
   * @return {DecryptParamsBuilder} - this object.
   */
  withStringSource(string: string): this {
    this.setStringSource(string);
    return this;
  }

  /**
   * Specify a reference to a local file with the TDF ciphertext to decrypt.
   * Only works with node.
   * @param source (node) the path of the local file to decrypt, or the Blob (browser/node)
   */
  setFileSource(source: Blob) {
    this._params.source = { type: 'file-browser', location: source };
  }

  /**
   * Specify a reference to a local file with the TDF ciphertext to decrypt. Only works with node.
   * Returns this object for method chaining.
   * @param source (node) the path of the local file to decrypt, or the Blob (browser/node)
   */
  withFileSource(source: Blob): this {
    this.setFileSource(source);
    return this;
  }

  /**
   * Specify the content to decrypt using an ArrayBuffer reference, which must have already
   * loaded the file content. Using the below linked example, e.target.result is the ArrayBuffer
   * <br/><br/>
   * Example: https://developer.mozilla.org/en-US/docs/Web/API/FileReader/onload
   *
   * @param {ArrayBuffer} arraybuffer - the array buffer containing the file to decrypt.
   * @return {DecryptParamsBuilder} - this object
   */
  setArrayBufferSource(arraybuffer: ArrayBuffer) {
    this.setBufferSource(new Uint8Array(arraybuffer));
  }

  /**
   * Specify the content to decrypt using an ArrayBuffer reference. Returns this object for method chaining.
   *
   * @param  {ArrayBuffer} arraybuffer - the ArrayBuffer used to load file content from a browser
   * @return {DecryptParamsBuilder} - this object.
   */
  withArrayBufferSource(arraybuffer: ArrayBuffer): this {
    this.setArrayBufferSource(arraybuffer);
    return this;
  }

  /** Skip assertion verification */
  withNoVerifyAssertions(v: boolean): DecryptParamsBuilder {
    this._params.noVerifyAssertions = v;
    return this;
  }

  /**
   * Sets the assertion verification keys for the decryption parameters.
   *
   * @param {AssertionVerificationKeys} assertionVerificationKeys - An array of assertion configurations to be set.
   * @returns {DecryptParamsBuilder} The current instance of the EncryptParamsBuilder for method chaining.
   */
  withAssertionVerificationKeys(
    assertionVerificationKeys: AssertionVerificationKeys
  ): DecryptParamsBuilder {
    this._params.assertionVerificationKeys = assertionVerificationKeys;
    return this;
  }

  _deepCopy(_params: DecryptParams) {
    return freeze({ ..._params });
  }

  withConcurrencyLimit(limit: number): DecryptParamsBuilder {
    this._params.concurrencyLimit = limit;
    return this;
  }

  /**
   * Generate a parameters object in the form expected by <code>{@link Client#decrypt|decrypt}</code>.
   * <br/><br/>
   * Creates a deep copy to prevent tricky call-by-reference and async execution bugs.
   */
  build(): Readonly<DecryptParams> {
    if (!this._params.source) {
      throw new ConfigurationError('No source specified');
    }
    return this._deepCopy(this._params as DecryptParams);
  }
}

export { DecryptParamsBuilder, EncryptParamsBuilder };
