import { TDF, Client } from './src/index.js';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index.js';
import { FileClient } from './src/FileClient.js';

window.TDF = TDF;

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
