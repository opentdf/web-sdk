import { TDF, Client, Errors } from './src/index';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index';
import { FileClient } from './src/FileClient';

import { webcrypto as crypto } from 'crypto';
import { ReadableStream } from 'stream/web';

import { registerModuleType } from './src/client/tdf-stream';
import { NodeTdfStream } from './src/client/NodeTdfStream';

globalThis.crypto ??= crypto as unknown as Crypto;
//@ts-expect-error assignment to any type
globalThis.CryptoKey ??= crypto.CryptoKey;
globalThis.ReadableStream ??= ReadableStream;
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
};
