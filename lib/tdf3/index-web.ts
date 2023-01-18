import { TDF, Client, Errors } from './src/index.js';
import {
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
  clientType,
} from '../src/index.js';
import { FileClient } from './src/FileClient.js';
import { AuthProvider, AppIdAuthProvider, HttpRequest } from '../src/auth/auth.js';
import { registerModuleType } from './src/client/tdf-stream.js';
import { BrowserTdfStream } from './src/client/BrowserTdfSteam.js';

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
