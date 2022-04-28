import { S3Client, GetObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import axios from 'axios';
import { createReadStream } from 'fs';
import { Readable } from 'stream';
import webStreams from 'web-streams-node';
import { arrayBufferToBuffer, inBrowser } from '../utils';
import { AttributeValidator } from './validation';
import { IllegalArgumentError, IllegalEnvError } from '../errors';

const { get } = axios;

export const DEFAULT_SEGMENT_SIZE = 1000 * 1000;

async function setRemoteStoreAsStream(fileName, config, credentialURL, builder) {
  let virtruTempS3Credentials;
  let storageParams;

  // Param validation
  if (!fileName) {
    throw new Error('Passing a fileName is required for setRemoteStore()');
  }

  if (credentialURL) {
    // Check for string or string object
    try {
      virtruTempS3Credentials = await get(credentialURL);
    } catch (e) {
      console.error(e);
    }
  }

  try {
    let BUCKET_NAME;
    if (config && config.Bucket) {
      BUCKET_NAME = config.Bucket;
    } else {
      BUCKET_NAME =
        virtruTempS3Credentials && virtruTempS3Credentials.data
          ? virtruTempS3Credentials.data.bucket
          : undefined;
    }
    const FILE_NAME = fileName;

    // Build a storage config object from 'config' or 'virtruTempS3Credentials'
    if (virtruTempS3Credentials) {
      storageParams = {
        credentials: {
          accessKeyId: virtruTempS3Credentials.data.fields.AWSAccessKeyId,
          secretAccessKey: virtruTempS3Credentials.data.fields.AWSSecretAccessKey,
          sessionToken: virtruTempS3Credentials.data.fields.AWSSessionToken,
          policy: virtruTempS3Credentials.data.fields.policy,
          signature: virtruTempS3Credentials.data.fields.signature,
          key: virtruTempS3Credentials.data.fields.key,
        },
        region: virtruTempS3Credentials.data.url.split('.')[1],
        signatureVersion: 'v4',
        s3ForcePathStyle: false,
        maxRetries: 3,
        useAccelerateEndpoint: true,
      };
    } else {
      storageParams = {
        ...config,
      };
    }

    const s3 = new S3Client(storageParams);

    const s3Metadata = await s3.send(
      new HeadObjectCommand({
        Key: FILE_NAME,
        Bucket: BUCKET_NAME,
      })
    );

    builder._params.contentLength = s3Metadata.ContentLength;

    const s3download = await s3.send(
      new GetObjectCommand({
        Key: FILE_NAME,
        Bucket: BUCKET_NAME,
      })
    );

    let s3Stream = s3download.Body;

    if (inBrowser()) {
      s3Stream = webStreams.toNodeReadable(s3download.Body);
    }

    builder.setStreamSource(s3Stream);
    return builder._deepCopy(builder._params);
  } catch (e) {
    console.error(e);
    throw e;
  }
}

/**
 * A builder capable of constructing the necessary parameters object for a
 * {@link Client#encrypt|encrypt} operation. Must be built before use via the {@link EncryptParamsBuilder#build|build()} function.
 */
class EncryptParamsBuilder {
  constructor() {
    // TODO: Turn this into a read-only params object like Policy in the virtru wrapper.
    this._params = {
      source: null,
      scope: {
        dissem: [],
        attributes: [],
      },
      metadata: {},
      keypair: undefined,
      offline: false,
      windowSize: DEFAULT_SEGMENT_SIZE,
      asHtml: false,
      rcaSource: false,
    };
  }

  getStreamSource() {
    return this._params.source;
  }

  /**
   * Specify the content to encrypt, in stream form.
   * @param {Readable} readStream - a Readable Stream to encrypt.
   */
  setStreamSource(readStream) {
    // TODO: Type check for ReadableStream.
    this._params.source = readStream;
  }

  /**
   * Specify the content to encrypt, in stream form. Returns this object for method chaining.
   * @param {Readable} readStream - a Readable Stream to encrypt.
   * @return {EncryptParamsBuilder} - this object.
   */
  withStreamSource(readStream) {
    this.setStreamSource(readStream);
    return this;
  }

  /**
   * Specify the remote content to encrypt in stream form.
   * withRemoteStore() has not been implemented because setRemoteStore() is async so withRemoteStore() can't be chained with a build() call.
   * @param {string} fileName - the name of the remote file to write TDF ciphertext to.
   * @param {S3ClientConfig} [config] - the object containing remote storage configuration.
   * <br>A detailed spec for the interface can be found [here]{@link https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-s3/interfaces/s3clientconfig.html}
   * @param {string} [credentialURL] - the url to request remote storage credentials from.
   * <br>Credentials can be generated using [GetFederationToken]{@link https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html}
   * @return {EncryptParamsBuilder} - this object.
   */
  async setRemoteStore(fileName, config, credentialURL) {
    return setRemoteStoreAsStream(fileName, config, credentialURL, this);
  }

  /**
   * Specify the content to encrypt, in string form.
   * @param {string} string - a string to encrypt.
   */
  setStringSource(string) {
    if (typeof string !== 'string') {
      throw new IllegalArgumentError('string source must be of type string');
    }
    const stream = new Readable();
    stream.push(string);
    stream.push(null);
    this.setStreamSource(stream);
  }

  /**
   * Specify the content to encrypt, in string form. Returns this object for method chaining.
   * @param {string} string - a string to encrypt.
   * @return {EncryptParamsBuilder} - this object.
   */
  withStringSource(string) {
    this.setStringSource(string);
    return this;
  }

  /**
   * Specify the content to encrypt, in buffer form.
   * @param {Buffer} buf - a buffer to encrypt.
   */
  setBufferSource(buf) {
    const stream = new Readable();
    stream.push(buf);
    stream.push(null);
    this.setStreamSource(stream);
  }

  /**
   * Specify the content to encrypt, in buffer form. Returns this object for method chaining.
   * @param {Buffer} buf - a buffer to encrypt
   * @return {EncryptParamsBuilder} - this object.
   */
  withBufferSource(buf) {
    this.setBufferSource(buf);
    return this;
  }

  /**
   * Specify the content to encrypt using a file reference. Only works with node.
   * @param {string} filepath - the location on disk of the file to encrypt.
   */
  setFileSource(filepath) {
    if (typeof filepath !== 'string') {
      throw new IllegalArgumentError('file source filepath must be of type string');
    }
    // TODO: Support browser files.
    this._params.source = createReadStream(filepath);
  }

  /**
   * Specify the content to encrypt using a file reference. Only works with node.
   * Returns this object for method chaining.
   * @param {string} filepath - the location on disk of the file to encrypt.
   * @return {EncryptParamsBuilder} - this object.
   */
  withFileSource(filepath) {
    this.setFileSource(filepath);
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
  setArrayBufferSource(arraybuffer) {
    if (!inBrowser()) {
      throw new IllegalEnvError("must be in a browser context to use 'withArrayBufferSource'");
    }

    this.setBufferSource(arrayBufferToBuffer(arraybuffer));
  }

  /**
   * Specify the content to encrypt using an ArrayBuffer reference. Returns this object for method chaining.
   *
   * @param  {ArrayBuffer} arraybuffer - the ArrayBuffer used to load file content from a browser
   * @return {EncryptParamsBuilder} - this object.
   */
  withArrayBufferSource(arraybuffer) {
    this.setArrayBufferSource(arraybuffer);
    return this;
  }

  getAttributes() {
    return this._params.scope.attributes;
  }

  /**
   * @param {Object} attributes
   * @param {String} attributes.attribute URI of the form `<authority namespace>/attr/<name>/value/<value>`
   */
  setAttributes(attributes) {
    AttributeValidator(attributes);
    this._params.scope.attributes = attributes;
  }

  /**
   * @param {Object} attributes
   * @param {String} attributes.attribute URI of the form `<authority namespace>/attr/<name>/value/<value>`
   * @returns {EncryptParamsBuilder} with attributes set
   */
  withAttributes(attributes) {
    this.setAttributes(attributes);
    return this;
  }

  /**
   * Get the users configured to access (decrypt) the encrypted data.
   * @return {array} - array of users (e.g., email addresses).
   */
  getUsersWithAccess() {
    return this._params.scope.dissem;
  }

  /**
   * Specify the full list of users configured to access (decrypt) the encrypted data.
   * @param {array} users - varargs or array of users (e.g., email addresses).
   */
  setUsersWithAccess(users) {
    if (!Array.isArray(users)) {
      throw new IllegalArgumentError('users must be an array');
    }
    this._params.scope.dissem = users;
  }

  /**
   * Specify the full list of users configured to access (decrypt) the encrypted data. Returns this object for method chaining.
   * <br/><br/>
   * @param {array} users - varargs or array of users (e.g., email addresses).
   * @return {EncryptParamsBuilder} - this object.
   */
  withUsersWithAccess(users) {
    this.setUsersWithAccess(users);
    return this;
  }

  /**
   * Get the metadata (arbitrary key-value pairs) to be associated with the encrypted blob.
   * </br></br>
   * This metadata is encrypted alongside the content and stored in the TDF ciphertext.
   * @return {object} - object containing metadata as key-value pairs.
   */
  getMetadata() {
    // TODO: Return deep copy?
    return this._params.metadata;
  }

  /**
   * Specify the metadata (arbitrary key-value pairs) to be associated with the encrypted blob.
   * </br></br>
   * This metadata is encrypted alongside the content and stored in the TDF ciphertext.
   * @param {object} metadata - object containing metadata as key-value pairs.
   */
  setMetadata(metadata) {
    if (typeof metadata !== 'object') {
      throw new IllegalArgumentError('metadata must be an object');
    }
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
  withMetadata(metadata) {
    this.setMetadata(metadata);
    return this;
  }

  getPolicyId() {
    return this._params.scope.policyId;
  }

  setPolicyId(policyId) {
    this._params.scope.policyId = policyId;
  }

  withPolicyId(policyId) {
    this.setPolicyId(policyId);
    return this;
  }

  isOnline() {
    return !this._params.offline;
  }

  setOnline() {
    this._params.offline = false;
  }

  setOffline() {
    this._params.offline = true;
  }

  withOffline() {
    this.setOffline();
    return this;
  }

  withOnline() {
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
  getStreamWindowSize() {
    return this._params.windowSize;
  }

  /**
   * Set the size of the sliding window to use when writing out the encrypted ciphertext.
   * Used to bound the memory used by the client for large files.
   * <br/><br/>
   * This window will match the "segment size" defined in the
   * <a href="https://github.com/virtru/tdf3-spec">TDF spec</a>, so a larger window
   * will result in more compact ciphertext.
   * @param {number} The sliding window size, in bytes (1MB by default).
   */
  setStreamWindowSize(numBytes) {
    if (!numBytes || numBytes <= 0) {
      throw new Error('Stream window size must be positive');
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
   * @param {number} The sliding window size, in bytes (1MB by default).
   * @return {EncryptParamsBuilder} - this object.
   */
  withStreamWindowSize(numBytes) {
    this.setStreamWindowSize(numBytes);
    return this;
  }

  /**
   * Whether the encrypted data should be formatted using html. This allows authorized users to
   * double click and read using the Virtru Secure Reader, at the cost of reduced space efficiency.
   * <br/><br/>
   * This is enabled by default.
   * @return {boolean} true if the encrypted data will be in html format.
   */
  hasHtmlFormat() {
    return this._params.asHtml;
  }

  /**
   * Specify that the encrypted data should be formatted using html. This allows authorized users to
   * double click and read using the Virtru Secure Reader, at the cost of reduced space efficiency.
   * <br/><br/>
   * This is enabled by default.
   */
  setHtmlFormat() {
    this._params.asHtml = true;
  }

  /**
   * Specify that the encrypted data should be formatted using html. This allows authorized users to
   * double click and read using the Virtru Secure Reader, at the cost of reduced space efficiency.
   * Returns this object for method chaining.
   * <br/><br/>
   * This is enabled by default.
   * @return {EncryptParamsBuilder} - this object.
   */
  withHtmlFormat() {
    this.setHtmlFormat();
    return this;
  }

  /**
   * Whether the encrypted data should be formatted using zip. This is more space efficient than html,
   * but authorized users must leverage the Virtru SDK to decrypt.
   * <br/><br/>
   * This is disabled by default (html is enabled by default).
   * @return {boolean} true if the encrypted data will be in zip format.
   */
  hasZipFormat() {
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
  withZipFormat() {
    this.setZipFormat();
    return this;
  }

  /**
   * @param isRcaSource{boolean}
   */
  setRcaSource(isRcaSource) {
    this._params.rcaSource = isRcaSource;
  }

  withRcaSource() {
    this.setRcaSource(true);
    return this;
  }

  /**
   * Gets the (consumer provided) mime type of the file to be protected
   */
  getMimeType() {
    return this._params.mimeType;
  }

  /**
   * Sets the mime type of the underlying file.
   * @param {string} mimeType - the content type string to be applied during decrypt
   * @return {EncryptParamsBuilder} - this object.
   */
  setMimeType(mimeType) {
    this._params.mimeType = mimeType;
  }

  /**
   * Sets the mime type of the underlying file.
   * @param {string} mimeType - the content type string to be applied during decrypt
   * @return {EncryptParamsBuilder} - this object.
   */
  withMimeType(mimeType) {
    this.setMimeType(mimeType);
    return this;
  }

  // Create a deep copy of the provided parameters object.
  _deepCopy(_params) {
    // TODO: static?
    const params = {
      source: _params.source,
      scope: {
        policyId: _params.scope.policyId,
        dissem: _params.scope.dissem.slice(0),
        attributes: _params.scope.attributes.slice(0),
      },
      metadata: { ..._params.metadata },
      ...(_params.mimeType && { mimeType: _params.mimeType }),
      ...(_params.contentLength && { contentLength: _params.contentLength }),
    };
    if (_params.keypair) {
      params.keypair = { ..._params.keypair };
    }
    params.offline = _params.offline;
    params.windowSize = _params.windowSize;
    params.asHtml = _params.asHtml;
    params.rcaSource = _params.rcaSource;
    // add a simple helper function for folks to grab uuids during/after encrypt.
    params.getPolicyId = () => {
      return params.scope.policyId;
    };
    return params;
  }

  /**
   * Generate a parameters object in the form expected by <code>{@link EncryptParamsBuilder#build|build()}</code>.
   * <br/><br/>
   * Creates a deep copy to prevent tricky call-by-reference and async execution bugs.
   */
  build() {
    return this._deepCopy(this._params);
  }
}

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
  constructor() {
    this._params = {
      source: null,
    };
  }

  getStreamSource() {
    return this._params.source;
  }

  /**
   * Set the TDF ciphertext to decrypt, in buffer form.
   * @param {Buffer} buf - a buffer to decrypt.
   */
  setBufferSource(buffer) {
    if (typeof buffer !== 'object') {
      throw new IllegalArgumentError(`buffer source must be of type object, was: ${buffer}`);
    }
    this._params.source = { type: 'buffer', location: buffer };
  }

  /**
   * Set the TDF ciphertext to decrypt, in buffer form. Returns this object for method chaining.
   * @param {Buffer} buf - a buffer to decrypt.
   * @return {DecryptParamsBuilder} - this object.
   */
  withBufferSource(buffer) {
    this.setBufferSource(buffer);
    return this;
  }

  /**
   * Specify the TDF ciphertext to decrypt, from an http(s) URL.
   * TODO: add support for TDF.html encoding
   * @param {string} url - a url pointing to a tdf3 file
   */
  setUrlSource(url) {
    if (!/^https?/.exec(url)) {
      throw new IllegalArgumentError(`stream source must be a web url, not [${url}]`);
    }
    this._params.source = { type: 'remote', location: url };
  }

  /**
   * Specify the TDF ciphertext to decrypt, as a URL.
   * @param {string} url - a tdf3 remote URL.
   * @return {DecryptParamsBuilder} - this object.
   */
  withUrlSource(url) {
    this.setUrlSource(url);
    return this;
  }

  /**
   * Specify the TDF ciphertext to decrypt, in stream form.
   * @param {Readable} stream - a Readable stream to decrypt.
   */
  setStreamSource(stream) {
    if (typeof stream !== 'object') {
      throw new IllegalArgumentError(`stream source must be of type object, was: ${stream}`);
    }
    this._params.source = { type: 'stream', location: stream };
  }

  /**
   * Specify the TDF ciphertext to decrypt, in stream form. Returns this object for method chaining.
   * @param {Readable} stream - a Readable stream to decrypt.
   * @return {DecryptParamsBuilder} - this object.
   */
  withStreamSource(stream) {
    this.setStreamSource(stream);
    return this;
  }

  /**
   * Specify the remote content to decrypt in stream form.
   * withRemoteStore() has not been implemented because setRemoteStore() is async so withRemoteStore() can't be chained with a build() call.
   * @param {string} fileName - the name of the remote file to write TDF ciphertext to.
   * @param {S3ClientConfig} [config] - the object containing remote storage configuration.
   * <br>A detailed spec for the interface can be found [here]{@link https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-s3/interfaces/s3clientconfig.html}
   * @param {string} [credentialURL] - the url to request remote storage credentials from.
   * <br>Credentials can be generated using [GetFederationToken]{@link https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html}
   * @return {DecryptParamsBuilder} - this object.
   */
  async setRemoteStore(fileName, config, credentialURL) {
    return setRemoteStoreAsStream(fileName, config, credentialURL, this);
  }

  /**
   * Specify the TDF ciphertext to decrypt, in string form.
   * @param {string} string - a string to decrypt.
   */
  setStringSource(string) {
    this.setBufferSource(Buffer.from(string, 'binary'));
  }

  /**
   * Specify the TDF ciphertext to decrypt, in string form. Returns this object for method chaining.
   * @param {string} string - a string to decrypt.
   * @return {DecryptParamsBuilder} - this object.
   */
  withStringSource(string) {
    this.setStringSource(string);
    return this;
  }

  /**
   * Specify a reference to a local file with the TDF ciphertext to decrypt.
   * Only works with node.
   * @param {string} filepath - the path of the local file to decrypt.
   */
  setFileSource(filepath) {
    if (typeof filepath !== 'string') {
      throw new IllegalArgumentError('file source filepath must be of type string');
    }
    if (typeof window !== 'undefined') {
      this._params.source = { type: 'file-browser', location: filepath };
    } else {
      this._params.source = { type: 'file-node', location: filepath };
    }
  }

  /**
   * Specify a reference to a local file with the TDF ciphertext to decrypt. Only works with node.
   * Returns this object for method chaining.
   * @param {string} filepath - the path of the local file to decrypt.
   * @return {DecryptParamsBuilder} - this object.
   */
  withFileSource(filepath) {
    this.setFileSource(filepath);
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
  setArrayBufferSource(arraybuffer) {
    if (!inBrowser()) {
      throw new IllegalEnvError("must be in a browser context to use 'withArrayBufferSource'");
    }

    this.setBufferSource(arrayBufferToBuffer(arraybuffer));
  }

  /**
   * Specify the content to decrypt using an ArrayBuffer reference. Returns this object for method chaining.
   *
   * @param  {ArrayBuffer} arraybuffer - the ArrayBuffer used to load file content from a browser
   * @return {DecryptParamsBuilder} - this object.
   */
  withArrayBufferSource(arraybuffer) {
    this.setArrayBufferSource(arraybuffer);
    return this;
  }

  /**
   * @param rcaParams
   */
  setRcaSource(rcaParams) {
    this._params.rcaSource = rcaParams;
  }

  /**
   * Use it with .withStreamSource
   * @param rcaParams
   * @returns {DecryptParamsBuilder}
   */
  withRcaSource(rcaParams) {
    this.setRcaSource(rcaParams);
    return this;
  }

  // Create a deep copy of the provided parameters object.
  _deepCopy(_params) {
    // TODO: static?
    const params = {
      source: _params.source,
      opts: {},
      ...(_params.contentLength && { contentLength: _params.contentLength }),
    };
    if (_params.keypair) {
      params.keypair = { ..._params.keypair };
    }
    params.rcaSource = _params.rcaSource;
    return params;
  }

  /**
   * Generate a parameters object in the form expected by <code>{@link Client#decrypt|decrypt}</code>.
   * <br/><br/>
   * Creates a deep copy to prevent tricky call-by-reference and async execution bugs.
   */
  build() {
    return this._deepCopy(this._params);
  }
}

export { DecryptParamsBuilder, EncryptParamsBuilder };
