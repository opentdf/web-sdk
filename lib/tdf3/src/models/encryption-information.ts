import { type KeyAccessObject } from './key-access.js';
import { IntegrityAlgorithm } from '../tdf.js';

export type Segment = {
  readonly hash: string;
  // If not present, segmentSizeDefault must be defined and used.
  readonly segmentSize?: number;
  // If not present, encryptedSegmentSizeDefault must be defined and used.??
  readonly encryptedSegmentSize?: number;
};

export type SplitType = 'split';

export type EncryptionInformation = {
  readonly type: SplitType;
  readonly keyAccess: KeyAccessObject[];
  readonly integrityInformation: {
    readonly rootSignature: {
      alg: IntegrityAlgorithm;
      sig: string;
    };
    segmentHashAlg?: IntegrityAlgorithm;
    segments: Segment[];
    segmentSizeDefault?: number;
    encryptedSegmentSizeDefault?: number;
  };
  readonly method: {
    readonly algorithm: string;
    isStreamable: boolean;
    readonly iv: string;
  };
  policy: string;
};
