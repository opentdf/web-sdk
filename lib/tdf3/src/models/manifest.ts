import { type Assertion } from './assertion.js';
import { type Payload } from './payload.js';
import { type EncryptionInformation } from './encryption-information.js';

export type Manifest = {
  payload: Payload;
  encryptionInformation: EncryptionInformation;
  assertions: Assertion[];
};
