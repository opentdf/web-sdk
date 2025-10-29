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

/**
 * Root class for all errors thrown by this library.
 * This should not be thrown directly, but rather one of its subclasses.
 */
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

/**
 * Errors that indicate the client or method does not have valid options.
 */
export class ConfigurationError extends TdfError {
  override name = 'ConfigurationError';
}

/**
 * The assigned data attribute is not in the correct form.
 */
export class AttributeValidationError extends ConfigurationError {
  override name = 'AttributeValidationError';
  attribute: unknown;
  constructor(message: string, attribute: unknown, cause?: Error) {
    super(message, cause);
    this.attribute = attribute;
  }
}

/**
 * Errors that indicate the TDF object is corrupt, invalid, or fails validation or decrypt.
 */
export class InvalidFileError extends TdfError {}

/**
 * Indicates a decrypt failure, either due to an incorrect key, corrupt ciphertext, or inappropriate key parameters.
 */
export class DecryptError extends InvalidFileError {
  override name = 'DecryptError';
}

export class IntegrityError extends InvalidFileError {
  override name = 'IntegrityError';
}

/**
 * Thrown when a KAS URL found in one or more required key access objects are not in the list of known and allowed KASes in the client.
 * This may indicate a malicious file - e.g. an attempt to DDoS a server by listing it as the KAS for many files, or to siphon credentials using a lookalike URL.
 */
export class UnsafeUrlError extends InvalidFileError {
  override name = 'UnsafeUrlError';
  readonly url: string[];

  constructor(message: string, ...url: string[]) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.url = url;
  }
}

/**
 * A network error (no response) from rewrap or other endpoint, Possibly fixed by retrying or adjusting your network settings; could indicate network failure.
 */
export class NetworkError extends TdfError {
  override name = 'NetworkError';
}

/**
 * The service reports an unexpected error on its behalf, or a subcomponent (5xx).
 */
export class ServiceError extends TdfError {
  override name = 'ServiceError';
}

/** Authentication failure (401) */
export class UnauthenticatedError extends TdfError {
  override name = 'UnauthenticatedError';
}

/** Authorization failure (403) */
export class PermissionDeniedError extends TdfError {
  override name = 'PermissionDeniedError';
  readonly requiredObligations?: string[];

  constructor(message: string, obligations?: string[], cause?: Error) {
    super(message, cause);
    if (obligations && obligations.length > 0) {
      this.requiredObligations = obligations;
    }
  }
}

/**
 * Version of file is unsupported, or file uses a feature that is not supported by this version of the library.
 */
export class UnsupportedFeatureError extends TdfError {
  override name = 'UnsupportedFeatureError';
}
