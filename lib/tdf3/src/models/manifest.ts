import { type Assertion } from '../assertions.js';
import { type Payload } from './payload.js';
import { type EncryptionInformation } from './encryption-information.js';

export type Manifest = {
  payload: Payload;
  encryptionInformation: EncryptionInformation;
  assertions: Assertion[];
  // Required in later versions, optional prior to 4.3.0
  schemaVersion?: string;
  // Deprecated
  tdf_spec_version?: string;
};
