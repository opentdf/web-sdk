import { Binary } from './src/binary.js';
import { DecoratedReadableStream } from './src/client/DecoratedReadableStream.js';
import {
  type DecryptParams,
  DecryptParamsBuilder,
  type DecryptSource,
  type EncryptParams,
  EncryptParamsBuilder,
} from './src/client/builders.js';
import { type SessionKeys, type ClientConfig, createSessionKeys } from './src/client/index.js';
import {
  type CryptoService,
  type DecryptResult,
  type EncryptResult,
  type PemKeyPair,
} from './src/crypto/declarations.js';
import { Client, Errors, TDF, TDF3Client } from './src/index.js';
import {
  type KeyInfo,
  SplitKey,
  type EncryptionInformation,
} from './src/models/encryption-information.js';
import { AuthProvider, AppIdAuthProvider, type HttpMethod, HttpRequest } from '../src/auth/auth.js';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index.js';
import { Algorithms, type AlgorithmName, type AlgorithmUrn } from './src/ciphers/algorithms.js';

window.TDF = TDF;

export type {
  AlgorithmName,
  AlgorithmUrn,
  CryptoService,
  DecryptResult,
  EncryptResult,
  HttpMethod,
  PemKeyPair,
};

export {
  Algorithms,
  AppIdAuthProvider,
  AuthProvider,
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
  SessionKeys,
  SplitKey,
  TDF,
  TDF3Client,
  clientType,
  createSessionKeys,
  version,
};
