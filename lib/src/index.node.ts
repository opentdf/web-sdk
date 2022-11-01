import { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType } from './index';
import { webcrypto as crypto } from 'crypto';
import { ReadableStream } from 'stream/web';

globalThis.crypto ??= crypto as unknown as Crypto;
globalThis.ReadableStream ??= ReadableStream;

export { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
// for cjs webpack build default export needed
export default { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
