import { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType } from './index';
import fetch from 'node-fetch'
// @ts-ignore
import crypto from 'crypto';

// @ts-ignore
globalThis.crypto = crypto;
// @ts-ignore
global.fetch = fetch;

export { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
// for cjs webpack build default export needed
export default { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType };
