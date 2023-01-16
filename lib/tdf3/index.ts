import { webcrypto as crypto } from 'crypto';
import { ReadableStream } from 'stream/web';

import { TDF, Client, Errors } from './src/index.js';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index.js';
import { FileClient } from './src/FileClient.js';
import { AuthProvider, AppIdAuthProvider, HttpRequest } from '../src/auth/auth.js';
import { registerModuleType } from './src/client/tdf-stream.js';
import { NodeTdfStream } from './src/client/NodeTdfStream.js';

if (globalThis) {
  globalThis.crypto ??= crypto as unknown as Crypto;
//@ts-expect-error assignment to any type
  globalThis?.CryptoKey ??= crypto.CryptoKey;
// @ts-expect-error transform type incompatible
  globalThis?.ReadableStream ??= ReadableStream;
}

registerModuleType(NodeTdfStream);

export {
  TDF,
  Errors,
  Client,
  version,
  clientType,
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  FileClient,
  AuthProvider,
  AppIdAuthProvider,
  HttpRequest,
};

export default {
  TDF,
  Errors,
  Client,
  version,
  clientType,
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  FileClient,
  AuthProvider,
  AppIdAuthProvider,
  HttpRequest,
};
