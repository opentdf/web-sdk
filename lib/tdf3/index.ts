import { TDF, Client, FileClient } from './src/index.js';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index.js';

import { webcrypto as crypto } from 'crypto';
import { ReadableStream } from 'stream/web';

import { registerModuleType } from './src/client/tdf-stream.js';
import { NodeTdfStream } from './src/client/NodeTdfStream.js';

globalThis.crypto ??= crypto as unknown as Crypto;
globalThis.ReadableStream ??= ReadableStream;
registerModuleType(NodeTdfStream);

export {
  TDF,
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
  Client,
  version,
  clientType,
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  FileClient,
};
