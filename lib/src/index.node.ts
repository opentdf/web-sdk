import { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType } from './index';
import fetch from 'node-fetch';
import { webcrypto as crypto } from 'node:crypto';

globalThis.crypto ??= crypto as unknown as Crypto;
globalThis.fetch ??= fetch as typeof globalThis.fetch;

export { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
// for cjs webpack build default export needed
export default { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
