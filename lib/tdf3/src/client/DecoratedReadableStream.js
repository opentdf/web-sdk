import { get } from 'axios';
import { S3Client } from '@aws-sdk/client-s3';
import { Upload } from '../utils/aws-lib-storage';
import stream from '@readableStream';

import { EventEmitter } from 'events';

class DecoratedReadableStream {
  constructor(byteLimit, underlyingSource) {
    this.stream = new stream.ReadableStream(underlyingSource, { highWaterMark: byteLimit });
    const ee = new EventEmitter();
    this.on = ee.on;
    this.emit = ee.emit;
  }

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
      Body: this,
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
}

export default DecoratedReadableStream;
