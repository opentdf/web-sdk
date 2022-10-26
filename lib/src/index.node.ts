import { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType } from './index';
import { webcrypto as crypto } from 'node:crypto';

globalThis.crypto ??= crypto as unknown as Crypto;

export { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
// for cjs webpack build default export needed
export default { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
