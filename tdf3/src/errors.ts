export class TdfError extends Error {
  override name = 'TdfError';

  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
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

export class ManifestIntegrityError extends TdfError {
  override name = 'ManifestIntegrityError';
}

export class PolicyIntegrityError extends TdfError {
  override name = 'PolicyIntegrityError';
}

export class TdfCorruptError extends TdfError {
  reason: string;

  override name = 'TdfCorruptError';

  constructor(message: string, err: Error, reason: string) {
    super(message);
    this.reason = reason;
  }
}
export class TdfDecryptError extends TdfError {
  override name = 'TdfDecryptError';
}

export class TdfPayloadExtractionError extends TdfError {
  override name = 'TdfPayloadExtractionError';
}
