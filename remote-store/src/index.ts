import {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
  S3ClientConfig,
  AbortMultipartUploadCommandOutput,
  CompleteMultipartUploadCommandOutput,
} from '@aws-sdk/client-s3';
import {
  DecryptParams,
  DecryptParamsBuilder,
  EncryptParams,
  EncryptParamsBuilder,
} from '@opentdf/client';
import axios from 'axios';

import { Upload } from './aws-lib-storage/index.js';
import { Options, Progress } from './aws-lib-storage/types.js';

export type VirtruS3Config = S3ClientConfig & {
  Bucket?: string;
};

export type VirtruCreds = S3ClientConfig['credentials'];

export type FetchCreds = {
  AWSAccessKeyId: string;
  AWSSecretAccessKey: string;
  AWSSessionToken: string;
};

export type VirtruTempS3Credentials = {
  data: {
    bucket: string;
    fields: FetchCreds;
    url: string;
  };
};

/**
 * Specify the remote content to encrypt in stream form.
 * withRemoteStore() has not been implemented because setRemoteStore() is async so withRemoteStore() can't be chained with a build() call.
 * @param builder A set of client params
 * @param fileName The name of the remote file to write TDF ciphertext to.
 * @param config The object containing remote storage configuration.
 * <br>A detailed spec for the interface can be found [here]{@link https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-s3/interfaces/s3clientconfig.html}
 * @param credentialURL The url to request remote storage credentials from.
 * <br>Credentials can be generated using [GetFederationToken]{@link https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html}
 * @return A Client options object
 */
export const setRemoteStoreAsStream = async (
  builder: DecryptParamsBuilder | EncryptParamsBuilder,
  fileName: string,
  config: VirtruS3Config,
  credentialURL?: string
): Promise<DecryptParams | EncryptParams> => {
  let virtruTempS3Credentials: VirtruTempS3Credentials | undefined;
  let storageParams: VirtruS3Config;

  // Param validation
  if (!fileName) {
    throw new Error('Passing a fileName is required for setRemoteStore()');
  }

  if (credentialURL) {
    // Check for string or string object
    virtruTempS3Credentials = await axios.get(credentialURL);
  }

  const BUCKET_NAME: string | undefined =
    config?.Bucket || virtruTempS3Credentials?.data?.bucket || undefined;

  const FILE_NAME: string = fileName;

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

  const s3 = new S3Client(storageParams);

  const s3Metadata = await s3.send(
    new HeadObjectCommand({
      Key: FILE_NAME,
      Bucket: BUCKET_NAME,
    })
  );

  if (typeof s3Metadata.ContentLength === 'number') {
    if ((builder as DecryptParamsBuilder).setContentLength) {
      (builder as DecryptParamsBuilder).setContentLength(s3Metadata.ContentLength);
    }
  }

  const s3download = await s3.send(
    new GetObjectCommand({
      Key: FILE_NAME,
      Bucket: BUCKET_NAME,
    })
  );

  const s3Stream = s3download.Body;

  builder.setStreamSource(s3Stream as ReadableStream<Uint8Array>);
  return builder.build();
};

/**
 *
 * Dump the stream content to remote storage. This will consume the stream.
 * @param {string} fileName - the name of the remote file to write TDF ciphertext to.
 * @param {S3ClientConfig} [config] - the object containing remote storage configuration.
 * <br>A detailed spec for the interface can be found [here]{@link https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-s3/interfaces/s3clientconfig.html}
 * @param {string} [credentialURL] - the url to request remote storage credentials from.
 * @return {RemoteUploadResponse} - an object containing metadata for the uploaded file.
 */
export const toRemoteStore = async (
  stream: ReadableStream<Uint8Array>,
  fileName: string,
  config: VirtruS3Config,
  credentialURL: string,
  progressHandler?: (event: Progress) => void
): Promise<CompleteMultipartUploadCommandOutput | AbortMultipartUploadCommandOutput> => {
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
    Body: stream,
  };

  const parallelUpload = new Upload({
    client: s3,
    queueSize: CONCURRENT_UPLOADS, // optional concurrency configuration
    partSize: MAX_UPLOAD_PART_SIZE, // optional size of each part, defaults to 5MB, cannot be smaller than 5MB
    leavePartsOnError: false, // optional manually handle dropped parts
    params: uploadParams,
  });

  if (progressHandler) {
    parallelUpload.on('httpUploadProgress', progressHandler);
  }

  return await parallelUpload.done();
};
