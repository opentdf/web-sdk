import { webcrypto as crypto } from 'crypto';
import { ReadableStream } from 'stream/web';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from './index.js';

globalThis.crypto ??= crypto as unknown as Crypto;
// @ts-expect-error transform type incompatible
globalThis.ReadableStream ??= ReadableStream;

export { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
