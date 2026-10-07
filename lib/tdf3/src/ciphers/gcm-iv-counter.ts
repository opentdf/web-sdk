import { ConfigurationError, IvExhaustionError } from '../../../src/errors.js';

const GCM_IV_LENGTH = 12;
const INVOCATION_FIELD_LENGTH = Uint32Array.BYTES_PER_ELEMENT;

/** Bytes of randomness a {@link GcmIvCounter} needs to seed one encryptor. */
export const GCM_FIXED_FIELD_LENGTH = GCM_IV_LENGTH - INVOCATION_FIELD_LENGTH;

/**
 * Invocations addressable by one fixed field, derived from the width of the
 * invocation field so the ceiling and the counter cannot drift apart.
 */
export const MAX_GCM_INVOCATIONS_PER_FIXED_FIELD = 2 ** (8 * INVOCATION_FIELD_LENGTH);

/**
 * The deterministic 96-bit AES-GCM IV construction of NIST SP 800-38D 8.2.1:
 * an 8-byte fixed field followed by a 4-byte big-endian invocation counter.
 *
 * The construction guarantees distinct IVs *within* one fixed field and
 * nothing more. Uniqueness across encryptors rests entirely on the fixed
 * field, so callers MUST draw a fresh random one for every counter -- through
 * the injected `CryptoService.randomBytes` -- even when the key is reused.
 * Repeating a fixed field
 * under a repeated key repeats IVs, which costs both confidentiality (the two
 * ciphertexts XOR to the XOR of their plaintexts) and authenticity (the GHASH
 * subkey becomes recoverable, so tags can be forged).
 */
export class GcmIvCounter {
  private readonly fixedField: Uint8Array;

  private nextInvocation: number;

  constructor(
    fixedField: Uint8Array,
    firstInvocation = 0,
    private readonly limit = MAX_GCM_INVOCATIONS_PER_FIXED_FIELD
  ) {
    if (fixedField.length !== GCM_FIXED_FIELD_LENGTH) {
      throw new ConfigurationError(
        `Invalid fixed field length: ${fixedField.length}; must be exactly ${GCM_FIXED_FIELD_LENGTH} bytes`
      );
    }
    if (!Number.isInteger(firstInvocation) || firstInvocation < 0) {
      throw new ConfigurationError(
        `Invalid first invocation: ${firstInvocation}; must be a non-negative integer`
      );
    }
    // `<=`, not `<`: a limit equal to the first invocation builds a counter
    // that can never issue an IV, which is a caller mistake rather than a
    // counter that merely starts out exhausted.
    if (!Number.isInteger(limit) || limit <= firstInvocation) {
      throw new ConfigurationError(
        `Invalid invocation limit: ${limit}; must be greater than ${firstInvocation}`
      );
    }
    if (limit > MAX_GCM_INVOCATIONS_PER_FIXED_FIELD) {
      throw new ConfigurationError(
        `Invalid invocation limit: ${limit}; exceeds the maximum of ${MAX_GCM_INVOCATIONS_PER_FIXED_FIELD} AES-GCM invocations per fixed field`
      );
    }
    // Copied so a caller that reuses or zeroes its randomness buffer cannot
    // change the IVs this counter has already committed to.
    this.fixedField = new Uint8Array(fixedField);
    this.nextInvocation = firstInvocation;
  }

  /** Return the next IV, consuming one invocation. */
  next(): Uint8Array {
    if (this.nextInvocation >= this.limit) {
      throw new IvExhaustionError(
        `Exceeded the maximum of ${this.limit} AES-GCM invocations for a single fixed field; the output stream is incomplete`
      );
    }
    const iv = this.ivFor(this.nextInvocation);
    this.nextInvocation += 1;
    return iv;
  }

  private ivFor(invocation: number): Uint8Array {
    // `setUint32` truncates modulo 2^32 without complaint, which would wrap
    // around onto an IV already issued instead of failing.
    if (
      !Number.isInteger(invocation) ||
      invocation < 0 ||
      invocation >= MAX_GCM_INVOCATIONS_PER_FIXED_FIELD
    ) {
      throw new ConfigurationError(`Invocation out of range: ${invocation}`);
    }
    const iv = new Uint8Array(GCM_IV_LENGTH);
    iv.set(this.fixedField);
    new DataView(iv.buffer).setUint32(GCM_FIXED_FIELD_LENGTH, invocation);
    return iv;
  }
}
