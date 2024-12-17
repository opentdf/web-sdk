import { Binary } from './src/binary.js';
import { DecoratedReadableStream } from './src/client/DecoratedReadableStream.js';
import {
  type DecryptParams,
  DecryptParamsBuilder,
  type DecryptSource,
  type EncryptParams,
  type EncryptKeyMiddleware,
  type EncryptStreamMiddleware,
  type DecryptKeyMiddleware,
  type DecryptStreamMiddleware,
  EncryptParamsBuilder,
  type SplitStep,
} from './src/client/builders.js';
import { type ClientConfig, createSessionKeys } from './src/client/index.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type PemKeyPair,
} from './src/crypto/declarations.js';
import { Client, Errors, TDF3Client } from './src/index.js';
import {
  type KeyInfo,
  SplitKey,
  type EncryptionInformation,
} from './src/models/encryption-information.js';
import { AuthProvider, type HttpMethod, HttpRequest, withHeaders } from '../src/auth/auth.js';
import { AesGcmCipher } from './src/ciphers/aes-gcm-cipher.js';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/nanoindex.js';
import { Algorithms, type AlgorithmName, type AlgorithmUrn } from './src/ciphers/algorithms.js';
import { type Chunker } from '../src/seekable.js';

export type {
  AlgorithmName,
  AlgorithmUrn,
  AuthProvider,
  Chunker,
  CryptoService,
  DecryptResult,
  EncryptResult,
  HttpMethod,
  PemKeyPair,
  EncryptKeyMiddleware,
  EncryptStreamMiddleware,
  DecryptKeyMiddleware,
  DecryptStreamMiddleware,
  SplitStep,
};

export {
  AesGcmCipher,
  Algorithms,
  AuthProviders,
  Binary,
  Client,
  ClientConfig,
  DecoratedReadableStream,
  DecryptParams,
  DecryptParamsBuilder,
  DecryptSource,
  EncryptionInformation,
  EncryptParams,
  EncryptParamsBuilder,
  Errors,
  HttpRequest,
  KeyInfo,
  NanoTDFClient,
  NanoTDFDatasetClient,
  SplitKey,
  TDF3Client,
  clientType,
  createSessionKeys,
  withHeaders,
  version,
};

export * as WebCryptoService from './src/crypto/index.js';
export {
  type CreateNanoTDFCollectionOptions,
  type CreateNanoTDFOptions,
  type CreateOptions,
  type CreateZTDFOptions,
  type DecoratedStream,
  type Keys,
  type OpenTDFOptions,
  type NanoTDFCollection,
  type ReadOptions,
  OpenTDF,
} from '../src/opentdf.js';
