function scrubCause(error?: Error, d?: number): { cause?: Error } {
  if (!error || (d && d > 4)) {
    return {};
  }
  if (!error.name) {
    return {};
  }
  const cause = new Error(error.name, scrubCause(error.cause as Error, (d || 0) + 1));
  if (error.message) {
    cause.message = error.message;
  }
  if (error.stack) {
    cause.stack = error.stack;
  }
  return { cause };
}

export class TdfError extends Error {
  override name = 'TdfError';

  constructor(message?: string, cause?: Error) {
    super(message, scrubCause(cause));
    // Error is funny (only on ES5? So  guess just IE11 we have to worry about?)
    // https://github.com/Microsoft/TypeScript-wiki/blob/main/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
    // https://stackoverflow.com/questions/41102060/typescript-extending-error-class#comment70895020_41102306
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class UnsafeUrlError extends Error {
  override name = 'UnsafeUrlError';
  readonly url: string;

  constructor(message: string, url: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.url = url;
  }
}

export class AttributeValidationError extends TdfError {
  override name = 'AttributeValidationError';
}

export class KasDecryptError extends TdfError {
  override name = 'KasDecryptError';
}

export class KasUpsertError extends TdfError {
  override name = 'KasUpsertError';
}

export class KeyAccessError extends TdfError {
  override name = 'KeyAccessError';
}

export class KeySyncError extends TdfError {
  override name = 'KeySyncError';
}

export class IllegalArgumentError extends Error {}

export class IllegalEnvError extends Error {}

export class InvalidCipherError extends TdfError {
  override name = 'InvalidCipherError';
}

export class InvalidCurveNameError extends TdfError {
  override name = 'InvalidCurveNameError';
}

export class InvalidDataTypeError extends TdfError {
  override name = 'InvalidDataTypeError';
}

export class InvalidEphemeralKeyError extends TdfError {
  override name = 'InvalidEphemeralKeyError';
}

export class InvalidPayloadError extends TdfError {
  override name = 'InvalidPayloadError';
}

export class InvalidPolicyTypeError extends TdfError {
  override name = 'InvalidPolicyTypeError';
}

export class ManifestIntegrityError extends TdfError {
  override name = 'ManifestIntegrityError';
}

export class PolicyIntegrityError extends TdfError {
  override name = 'PolicyIntegrityError';
}

export class SignatureError extends TdfError {
  override name = 'SignatureError';
}

export class TdfCorruptError extends TdfError {
  reason: string;

  override name = 'TdfCorruptError';

  constructor(message: string, err: Error, reason: string) {
    super(message, err);
    this.reason = reason;
  }
}
export class TdfDecryptError extends TdfError {
  override name = 'TdfDecryptError';
}

export class TdfPayloadExtractionError extends TdfError {
  override name = 'TdfPayloadExtractionError';
}
