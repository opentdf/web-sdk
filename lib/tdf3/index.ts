import { TDF, Client } from './src/index';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index';
import { FileClient } from './src/FileClient';

import { webcrypto as crypto } from 'node:crypto';
import { ReadableStream } from 'node:stream/web';

globalThis.crypto ??= crypto as unknown as Crypto;
globalThis.ReadableStream ??= ReadableStream;

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
