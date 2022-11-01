import axios from 'axios';
import {
  AbortMultipartUploadCommandOutput,
  CompleteMultipartUploadCommandOutput,
  S3Client,
} from '@aws-sdk/client-s3';
import { VirtruS3Config, VirtruTempS3Credentials, VirtruCreds } from './builders';
import { Upload } from '../utils/aws-lib-storage/index';
import { Options } from '../utils/aws-lib-storage/types';
import Metadata from '../tdf';

import { EventEmitter } from 'events';
import { Manifest } from '../models/index';

export async function streamToBuffer(stream: ReadableStream<Uint8Array>): Promise<Buffer> {
  const reader = stream.getReader();
  let accumulator = new Uint8Array();
  let done = false;

  while (!done) {
    const result = await reader.read();
    if (result.value) {
      const chunk = new Uint8Array(accumulator.byteLength + result.value.byteLength);
      chunk.set(new Uint8Array(accumulator), 0);
      chunk.set(new Uint8Array(result.value), accumulator.byteLength);
      accumulator = chunk;
    }
    done = result.done;
  }

  return Buffer.from(accumulator.buffer);
}

export abstract class DecoratedReadableStream {
  KEK: string;
  algorithm: string;
  tdfSize: number;
  stream: ReadableStream<Uint8Array>;
  on: NodeJS.EventEmitter['on'];
  emit: NodeJS.EventEmitter['emit'];
  metadata?: Metadata;
  contentLength?: number;
  manifest: Manifest;
  // upsertResponse: void[];

  constructor(byteLimit: number, underlyingSource: UnderlyingSource) {
    this.stream = new ReadableStream(underlyingSource, { highWaterMark: byteLimit });
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
  async toRemoteStore(
    fileName: string,
    config: VirtruS3Config,
    credentialURL: string
  ): Promise<CompleteMultipartUploadCommandOutput | AbortMultipartUploadCommandOutput> {
    // State
    const CONCURRENT_UPLOADS = 6;
    const MAX_UPLOAD_PART_SIZE = 1024 * 1024 * 5; // 5MB
    let storageParams: VirtruS3Config;
    let virtruTempS3Credentials: VirtruTempS3Credentials | undefined;

    // Param validation
    if (!config) {
      try {
        virtruTempS3Credentials = await axios.get(credentialURL);
      } catch (e) {
        console.error(e);
      }
    }

    // Build a storage config object from 'config' or 'virtruTempS3Credentials'
    if (virtruTempS3Credentials) {
      const credentials: VirtruCreds = {
        accessKeyId: virtruTempS3Credentials.data.fields.AWSAccessKeyId,
        secretAccessKey: virtruTempS3Credentials.data.fields.AWSSecretAccessKey,
        sessionToken: virtruTempS3Credentials.data.fields.AWSSessionToken,
      };

      storageParams = {
        credentials,
        region: virtruTempS3Credentials.data.url.split('.')[1],
        forcePathStyle: false,
        maxAttempts: 3,
        useAccelerateEndpoint: true,
      };
    } else {
      storageParams = config;
    }

    const BUCKET_NAME: string | undefined =
      config?.Bucket || virtruTempS3Credentials?.data?.bucket || undefined;

    const FILE_NAME = fileName || 'upload.tdf';

    const s3 = new S3Client(storageParams);

    // Managed Parallel Upload
    const uploadParams: Options['params'] = {
      Bucket: BUCKET_NAME,
      Key: FILE_NAME,
      Body: this.stream,
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
        this.on('rewrap', (rewrapResponse: Metadata) => {
          this.metadata = rewrapResponse;
          resolve(rewrapResponse);
        });
      }
    });
  }

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return the plaintext in Buffer form.
   */
  abstract toBuffer(): Promise<Buffer>;

  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return the plaintext in string form.
   */
  abstract toString(): Promise<string>;

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param filepath - the path of the local file to write plaintext to.
   */
  abstract toFile(filepath: string, encoding: BufferEncoding): Promise<void>;
}
