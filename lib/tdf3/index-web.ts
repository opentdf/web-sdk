import { TDF, Client, Errors } from './src/index';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index';
import { FileClient } from './src/FileClient';
import { AuthProvider, AppIdAuthProvider, HttpRequest } from '../src/auth/auth';
import { registerModuleType } from './src/client/tdf-stream';
import { BrowserTdfStream } from './src/client/BrowserTdfSteam';

registerModuleType(BrowserTdfStream);

window.TDF = TDF;

export {
  TDF,
  Errors,
  Client,
  version,
  clientType,
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  FileClient,
  AuthProvider,
  AppIdAuthProvider,
  HttpRequest,
};
