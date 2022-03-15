import { NanoTDFClient, NanoTDFDatasetClient } from './index';
import { AuthProviders } from './index';

// @ts-ignore
window.NanoTDFClient = NanoTDFClient;
// @ts-ignore
window.NanoTDFDatasetClient = NanoTDFDatasetClient;
// @ts-ignore
window.clientAuthProvider = AuthProviders.clientAuthProvider;

export {NanoTDFClient, NanoTDFDatasetClient, AuthProviders };
