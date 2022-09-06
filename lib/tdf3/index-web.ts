import { TDF, Client } from './src/index';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index';
import { FileClient } from './src/FileClient';

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
