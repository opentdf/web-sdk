import { type Payload } from './payload';
import { type EncryptionInformation } from './encryption-information';

export type Manifest = {
  payload: Payload;
  encryptionInformation: EncryptionInformation;
};
