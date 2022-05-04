import { get } from 'axios';
import { saveAs } from 'file-saver';
import { createWriteStream } from 'fs';
import { PassThrough } from 'stream';
import { toWebReadableStream } from 'web-streams-node';
import { WritableStream } from 'web-streams-polyfill/ponyfill';
import { Upload } from '@aws-sdk/lib-storage';
import { S3Client } from '@aws-sdk/client-s3';
import { streamToBuffer, inBrowser } from '../utils';

async function streamToString(stream, encoding) {
  return streamToBuffer(stream).then((res) => res.toString(encoding || 'utf8'));
}

/**
 * A {@link https://nodejs.org/api/stream.html#stream_class_stream_readable|Readable} stream implementation that exposes convenience methods for writing
 * to various locations like files and strings.
 * <pre>
 // Run a decrypt, which returns a PlaintextStream.
 plaintextStream = await client.decrypt(decryptParams);

 // PlaintextStream exposes a progress event emitter when toRemoteStore() is called on it.
 plaintextStream.toRemoteStore(fileName);

 plaintextStream.on('progress', progress => {
   console.log(`Uploaded ${progress.loaded} bytes`);
 });

 // Write the plaintext to a local file.
 await stream.toFile("/tmp/plain.txt");
   </pre>
 * @see Client#encrypt
 * @hideconstructor
 */
export class PlaintextStream extends PassThrough {
  constructor(byteLimit) {
    // see: https://nodejs.org/api/stream.html#stream_buffering
    super({ highWaterMark: byteLimit });
  }

  /**
   * Dump the stream content to a string. This will consume the stream.
   * @param {string} encoding - the charset encoding to use. Defaults to utf-8.
   * @return {string} - the plaintext in string form.
   */
  async toString(encoding) {
    return streamToString(this, encoding);
  }

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return {Buffer} - the plaintext in Buffer form.
   */
  async toBuffer() {
    return streamToBuffer(this);
  }

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param {string} filepath - the path of the local file to write plaintext to.
   * @param {string} encoding - the charset encoding to use. Defaults to utf-8.
   */
  async toFile(filepath, encoding) {
    if (inBrowser()) {
      const streamSaver = require('streamsaver');
      try {
        new streamSaver.WritableStream();
      } catch (e) {
        // Conditionally add ponyfill for Firefox
        streamSaver.WritableStream = WritableStream;
      }

      const webReadableStream = toWebReadableStream(this);

      const fileName = filepath || 'download.tdf';

      const fileStream = streamSaver.createWriteStream(fileName, {
        ...(this.contentLength && { size: this.contentLength }),
      });

      if (WritableStream && webReadableStream.pipeTo) {
        return webReadableStream.pipeTo(fileStream);
      }

      // Write (pipe) manually
      const writer = fileStream.getWriter();
      const reader = webReadableStream.getReader();
      const pump = () =>
        reader
          .read()
          .then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
      pump();
    }

    return new Promise((resolve, reject) => {
      const file = createWriteStream(filepath, { encoding: encoding || 'utf-8', flag: 'w' });
      this.pipe(file);
      file.on('finish', () => {
        resolve();
      });
      file.on('error', reject);
    });
  }

  /**
   * Metadata from an upload to a remote store.
   * @typedef {Object} RemoteUploadResponse
   * @property {string} Bucket - The bucket the file was uploaded to.
   * @property {string} Key - The filename given to the uploaded file.
   * @property {string} Location - The URL representing the location of the uploaded file.
   */

  /**
   *
   * Dump the stream content to remote storage. This will consume the stream.
   * @param {string} fileName - the name of the remote file to write TDF ciphertext to.
   * @param {S3ClientConfig} [config] - the object containing remote storage configuration.
   * <br>A detailed spec for the interface can be found [here]{@link https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-s3/interfaces/s3clientconfig.html}
   * @param {string} [credentialURL] - the url to request remote storage credentials from.
   * @return {RemoteUploadResponse} - an object containing metadata for the uploaded file.
   */
  async toRemoteStore(fileName, config, credentialURL) {
    // State
    const CONCURRENT_UPLOADS = 6;
    const MAX_UPLOAD_PART_SIZE = 1024 * 1024 * 5; // 5MB
    let storageParams;
    let virtruTempS3Credentials;

    // Param validation
    if (!config) {
      try {
        virtruTempS3Credentials = await get(credentialURL);
      } catch (e) {
        console.error(e);
      }
    }

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

    let BUCKET_NAME;
    if (config && config.Bucket) {
      BUCKET_NAME = config.Bucket;
    } else {
      BUCKET_NAME =
        virtruTempS3Credentials && virtruTempS3Credentials.data
          ? virtruTempS3Credentials.data.bucket
          : undefined;
    }

    const FILE_NAME = fileName || 'upload.tdf';

    const s3 = new S3Client(storageParams);

    // Managed Parallel Upload
    const uploadParams = {
      Bucket: BUCKET_NAME,
      Key: FILE_NAME,
      Body: toWebReadableStream(this),
    };

    try {
      const parallelUpload = new Upload({
        client: s3,
        queueSize: CONCURRENT_UPLOADS, // optional concurrency configuration
        partSize: MAX_UPLOAD_PART_SIZE, // optional size of each part, defaults to 5MB, cannot be smaller than 5MB
        leavePartsOnError: false, // optional manually handle dropped parts
        params: uploadParams,
      });

      parallelUpload.on('httpUploadProgress', (progress) => {
        this.emit('progress', progress);
      });

      return await parallelUpload.done();
    } catch (e) {
      console.error(e);
      throw e;
    }
  }

  _saveFile(filedata, { mime }, filename) {
    const blob = new Blob([filedata], { type: mime });
    saveAs(blob, filename);
  }

  getBufferedLength() {
    // For some reason, local and buildkite PassThrough have different properties. So we unify them here.
    const readableLength = this.readableLength || this._readableState.length;
    const writableLength = this.writableLength || this._writableState.length;
    return readableLength + writableLength;
  }

  async getMetadata() {
    return new Promise((resolve, reject) => {
      if (this.metadata) {
        resolve(this.metadata);
      } else {
        this.on('error', reject);
        this.on('rewrap', (rewrapResponse) => {
          this.metadata = rewrapResponse;
          resolve(rewrapResponse);
        });
      }
    });
  }

  write(chunk, cb) {
    super.write(chunk, cb);
    // By default PassThrough simply delegates to WritableStream, which only checks the write buffer.
    // But we want to ensure the read buffer is being consumed, so take that into consideration as well.
    return this.getBufferedLength() < this.readableHighWaterMark;
  }
}
