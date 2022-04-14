export { NanoTDFClient, NanoTDFDatasetClient, AuthProviders, version, clientType } from './index';
import crypto from 'crypto';

// @ts-ignore
globalThis.crypto = crypto;
