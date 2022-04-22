export class TdfError extends Error {
  message: string;

  err?: Error;

  name = 'TdfError';

  constructor(message: string, err?: Error) {
    super(message);
    // Error is funny (only on ES5? So  guess just IE11 we have to worry about?)
    // https://github.com/Microsoft/TypeScript-wiki/blob/main/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
    // https://stackoverflow.com/questions/41102060/typescript-extending-error-class#comment70895020_41102306
    Object.setPrototypeOf(this, new.target.prototype);
    this.err = err;
  }
}

export class AttributeValidationError extends TdfError {
  name = 'AttributeValidationError';
}

export class KasDecryptError extends TdfError {
  name = 'KasDecryptError';
}

export class KasUpsertError extends TdfError {
  name = 'KasUpsertError';
}

export class KeyAccessError extends TdfError {
  name = 'KeyAccessError';
}

export class KeySyncError extends TdfError {
  name = 'KeySyncError';
}

export class IllegalArgumentError extends Error {}

export class IllegalEnvError extends Error {}

export class ManifestIntegrityError extends TdfError {
  name = 'ManifestIntegrityError';
}

export class PolicyIntegrityError extends TdfError {
  name = 'PolicyIntegrityError';
}

export class TdfCorruptError extends TdfError {
  reason: string;

  name = 'TdfCorruptError';

  constructor(message: string, err: Error, reason: string) {
    super(message, err);
    this.reason = reason;
  }
}
export class TdfDecryptError extends TdfError {
  name = 'TdfDecryptError';
}

export class TdfPayloadExtractionError extends TdfError {
  name = 'TdfPayloadExtractionError';
}
