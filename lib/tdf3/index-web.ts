import { FileClient } from './src/FileClient.js';
import { Binary } from './src/binary.js';
import { DecoratedReadableStream } from './src/client/DecoratedReadableStream.js';
import { BrowserTdfStream } from './src/client/BrowserTdfSteam.js';
import {
  type DecryptParams,
  DecryptParamsBuilder,
  type DecryptSource,
  type EncryptParams,
  EncryptParamsBuilder,
} from './src/client/builders.js';
import { type SessionKeys, type ClientConfig, createSessionKeys } from './src/client/index.js';
import { type AnyTdfStream, registerModuleType } from './src/client/tdf-stream.js';
import { type DecryptResult, type EncryptResult } from './src/crypto/declarations.js';
import { TDF, Client, Errors } from './src/index.js';
import {
  type KeyInfo,
  SplitKey,
  type EncryptionInformation,
} from './src/models/encryption-information.js';
import { AuthProvider, AppIdAuthProvider, HttpRequest } from '../src/auth/auth.js';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index.js';

registerModuleType(BrowserTdfStream);

window.TDF = TDF;

export {
  AnyTdfStream,
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
  FileClient,
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
