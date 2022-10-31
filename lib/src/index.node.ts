import { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType } from './index';
import { webcrypto as crypto } from 'node:crypto';
import { ReadableStream } from 'node:stream/web';

globalThis.crypto ??= crypto as unknown as Crypto;
globalThis.ReadableStream ??= ReadableStream;

export { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
// for cjs webpack build default export needed
export default { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
