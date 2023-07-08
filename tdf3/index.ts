import { Client, Errors, TDF } from './src/index.js';
import { Binary } from './src/binary.js';
import { DecoratedReadableStream } from './src/client/DecoratedReadableStream.js';
import {
  type DecryptParams,
  DecryptParamsBuilder,
  type DecryptSource,
  type EncryptParams,
  EncryptParamsBuilder,
} from './src/client/builders.js';
import { type ClientConfig, createSessionKeys, type SessionKeys } from './src/client/index.js';
import { type DecryptResult, type EncryptResult } from './src/crypto/declarations.js';
import { type EncryptionInformation, type KeyInfo, SplitKey } from './src/models/index.js';
import { AppIdAuthProvider, AuthProvider, HttpRequest } from '../src/auth/auth.js';
import {
  AuthProviders,
  clientType,
  NanoTDFClient,
  NanoTDFDatasetClient,
  version,
} from '../src/index.js';

window.TDF = TDF;

export {
  AppIdAuthProvider,
  AuthProvider,
  AuthProviders,
  Binary,
  Client,
  ClientConfig,
  DecoratedReadableStream,
  DecryptParams,
  DecryptParamsBuilder,
  DecryptResult,
  DecryptSource,
  EncryptionInformation,
  EncryptParams,
  EncryptParamsBuilder,
  EncryptResult,
  Errors,
  HttpRequest,
  KeyInfo,
  NanoTDFClient,
  NanoTDFDatasetClient,
  SessionKeys,
  SplitKey,
  TDF,
  clientType,
  createSessionKeys,
  version,
};
