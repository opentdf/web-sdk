import {
  AbortMultipartUploadCommandOutput,
  CompleteMultipartUploadCommandOutput,
  S3Client,
} from '@aws-sdk/client-s3';
import axios from 'axios';
import { EventEmitter } from 'events';
import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils.js';

import { VirtruS3Config, VirtruTempS3Credentials, VirtruCreds } from './builders.js';
import { Upload } from '../utils/aws-lib-storage/index.js';
import { Options } from '../utils/aws-lib-storage/types.js';
import { type Metadata } from '../tdf.js';
import { type Manifest, type UpsertResponse } from '../models/index.js';

export async function streamToBuffer(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const accumulator = await new Response(stream).arrayBuffer();
  return new Uint8Array(accumulator);
}

export type DecoratedReadableStreamSinkOptions = {
  encoding?: BufferEncoding;
  signal?: AbortSignal;
};

export class DecoratedReadableStream {
  KEK: null | string;
  algorithm: string;
  policyUuid?: string;
  tdfSize: number;
  fileSize: number | undefined;
  stream: ReadableStream<Uint8Array>;
  ee: EventEmitter;
  on: EventEmitter['on'];
  emit: EventEmitter['emit'];
  metadata?: Metadata;
  contentLength?: number;
  manifest: Manifest;
  upsertResponse?: UpsertResponse;
  fileStreamServiceWorker?: string;

  constructor(
    underlyingSource: UnderlyingSource & {
      fileStreamServiceWorker?: string;
    }
  ) {
    if (underlyingSource.fileStreamServiceWorker) {
      this.fileStreamServiceWorker = underlyingSource.fileStreamServiceWorker;
    }
    this.stream = new ReadableStream(underlyingSource, {
      highWaterMark: 1,
    }) as ReadableStream<Uint8Array>;
    this.ee = new EventEmitter();
    this.on = (...args) => this.ee.on(...args);
    this.emit = (...args) => this.ee.emit(...args);
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
  async toBuffer(): Promise<Uint8Array> {
    return streamToBuffer(this.stream);
  }

  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return the plaintext in string form.
   */
  async toString(): Promise<string> {
    return new Response(this.stream).text();
  }

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param filepath The path of the local file to write plaintext to.
   * @param encoding The charset encoding to use. Defaults to utf-8.
   */
  async toFile(
    filepath = 'download.tdf',
    options?: BufferEncoding | DecoratedReadableStreamSinkOptions
  ): Promise<void> {
    if (options && typeof options === 'string') {
      throw new Error('Unsupported Operation: Cannot set encoding in browser');
    }
    if (isFirefox()) {
      await fileSave(new Response(this.stream), {
        fileName: filepath,
        extensions: [`.${filepath.split('.').pop()}`],
      });
      return;
    }

    if (this.fileStreamServiceWorker) {
      streamSaver.mitm = this.fileStreamServiceWorker;
    }

    const fileStream = streamSaver.createWriteStream(filepath, {
      ...(this.contentLength && { size: this.contentLength }),
      writableStrategy: { highWaterMark: 1 },
      readableStrategy: { highWaterMark: 1 },
    });

    if (WritableStream) {
      return this.stream.pipeTo(fileStream, options);
    }

    // Write (pipe) manually
    const reader = this.stream.getReader();
    const writer = fileStream.getWriter();
    const pump = async (): Promise<void> => {
      const res = await reader.read();

      if (res.done) {
        return await writer.close();
      } else {
        await writer.write(res.value);
        return pump();
      }
    };
    return pump();

    // const pump = (): Promise<void> =>
    //   reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    // pump();
  }
}

export function isDecoratedReadableStream(s: unknown): s is DecoratedReadableStream {
  return (
    typeof (s as DecoratedReadableStream)?.toBuffer !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toFile !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toString !== 'undefined'
  );
}
