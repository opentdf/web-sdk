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

export function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
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
 * The range given to decrypt selected portions of ciphertext is malformed
 * (offset or length not a non-negative safe integer) or cannot be satisfied
 * (offset past the end of the decrypted data). An offset equal to the size of
 * the decrypted data is valid and returns nothing. The end is the size recorded
 * in the manifest, checked before the file is authenticated, so a tampered file
 * can also cause this.
 */
export class DecryptRangeError extends ConfigurationError {
  override name = 'DecryptRangeError';
}

/**
 * Errors that indicate the TDF object is corrupt, invalid, or fails validation or decrypt.
 */
export class InvalidFileError extends TdfError {
  override name = 'InvalidFileError';
}

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
 * Stable reasons an assertion, or the manifest that carries it, can fail. The
 * strings are shared with the Go and Java SDKs and appear in error messages as
 * `reason=<code>`.
 *
 * `invalid-statement` is reserved; nothing reports it yet.
 */
export const ASSERTION_FAILURE_REASONS = [
  'invalid-json',
  'duplicate-member',
  'ambiguous-member',
  'invalid-id',
  'invalid-statement',
  'invalid-binding',
  'unsupported-binding',
  'unsupported-algorithm',
  'algorithm-mismatch',
  'invalid-embedded-key',
  'signer-not-permitted',
  'signature-invalid',
  'binding-mismatch',
  'configuration-error',
] as const;

/** One of {@link ASSERTION_FAILURE_REASONS}. */
export type AssertionFailureReason = (typeof ASSERTION_FAILURE_REASONS)[number];

const MAX_RENDERED_ID_CODE_POINTS = 256;

const SHORT_ESCAPES: Record<number, string> = {
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
  0x5c: '\\\\',
};

/**
 * Render an untrusted assertion id for an error message. Backslashes and
 * control characters (U+0000-U+001F, U+007F-U+009F) are escaped JSON-style,
 * and an id longer than 256 code points is cut there and ends with `…`, so an
 * id cannot start a new log line or bury the reason.
 */
function renderAssertionId(id: string): string {
  const codePoints = Array.from(id);
  let rendered = '';
  for (const ch of codePoints.slice(0, MAX_RENDERED_ID_CODE_POINTS)) {
    const c = ch.codePointAt(0)!;
    if (c === 0x5c || c <= 0x1f || (c >= 0x7f && c <= 0x9f)) {
      rendered += SHORT_ESCAPES[c] ?? `\\u${c.toString(16).padStart(4, '0')}`;
    } else {
      rendered += ch;
    }
  }
  return codePoints.length > MAX_RENDERED_ID_CODE_POINTS ? `${rendered}…` : rendered;
}

/**
 * An assertion failed verification, or the manifest failed the strict parsing
 * that assertion verification depends on (duplicate or ambiguous member names,
 * or JSON that is not I-JSON inside an assertion).
 *
 * The message contains `reason=<code>` and, when the assertion's `id` is known,
 * `id: <id>` with control characters escaped and long ids shortened;
 * {@link assertionId} keeps the exact id.
 */
export class AssertionVerificationError extends IntegrityError {
  override name = 'AssertionVerificationError';
  /** Why verification failed. */
  readonly reason: AssertionFailureReason;
  /** The exact `id` of the failing assertion, when one could be read. */
  readonly assertionId?: string;
  /** What failed, in more detail than the reason. */
  readonly detail?: string;

  constructor(
    reason: AssertionFailureReason,
    detail?: string,
    assertionId?: string,
    cause?: Error
  ) {
    const id = assertionId === undefined ? '' : `, id: ${renderAssertionId(assertionId)}`;
    super(
      `assertion integrity check failed${id}, reason=${reason}${detail ? `: ${detail}` : ''}`,
      cause
    );
    this.reason = reason;
    if (assertionId !== undefined) {
      this.assertionId = assertionId;
    }
    if (detail) {
      this.detail = detail;
    }
  }
}

/**
 * A write used up the AES-GCM invocation budget for a single data encryption
 * key. Payload segments use random 96-bit IVs, so the chance of an IV
 * collision grows with the square of the segment count; NIST SP 800-38D §8.3
 * therefore allows at most 2^32 invocations per key, and the writer stops
 * before the segment that would exceed it. Not a
 * `ConfigurationError`: the options were valid, and many segments were
 * encrypted before the budget ran out. The partial output is unusable and must
 * be discarded; retry with a larger segment size or split the input.
 */
export class IvExhaustionError extends TdfError {
  override name = 'IvExhaustionError';
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

/**
 * One or more attribute value FQNs were not found on the platform.
 * Thrown by {@link validateAttributes} and {@link validateAttributeValue} when the platform
 * does not recognize the requested FQNs.
 */
export class AttributeNotFoundError extends TdfError {
  override name = 'AttributeNotFoundError';
}
