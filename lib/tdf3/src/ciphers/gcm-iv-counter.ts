import { ConfigurationError } from '../../../src/errors.js';

const GCM_IV_LENGTH = 12;

/**
 * Conservative ceiling for authenticated-encryption invocations under one
 * BaseTDF payload key. Invocation zero is reserved for encrypted metadata.
 */
export const MAX_GCM_INVOCATIONS_PER_KEY = 2 ** 32;

/** A deterministic, unsigned 96-bit big-endian AES-GCM IV counter. */
export class GcmIvCounter {
  private nextInvocation: number;

  constructor(
    firstInvocation = 1,
    private readonly limit = MAX_GCM_INVOCATIONS_PER_KEY
  ) {
    if (!Number.isInteger(firstInvocation) || firstInvocation < 1) {
      throw new ConfigurationError(
        `Invalid first invocation: ${firstInvocation}; invocation 0 is reserved for metadata`
      );
    }
    if (!Number.isInteger(limit) || limit < firstInvocation) {
      throw new ConfigurationError(
        `Invalid invocation limit: ${limit}; must be at least ${firstInvocation}`
      );
    }
    if (limit > MAX_GCM_INVOCATIONS_PER_KEY) {
      throw new ConfigurationError(
        `Invalid invocation limit: ${limit}; exceeds the maximum of ${MAX_GCM_INVOCATIONS_PER_KEY} AES-GCM invocations per key`
      );
    }
    this.nextInvocation = firstInvocation;
  }

  /** The all-zero IV reserved for encrypted BaseTDF metadata. */
  static metadataIv(): Uint8Array {
    return new Uint8Array(GCM_IV_LENGTH);
  }

  /** Return the next payload IV, starting at invocation one. */
  next(): Uint8Array {
    if (this.nextInvocation >= this.limit) {
      throw new ConfigurationError(
        `Exceeded the maximum of ${this.limit} AES-GCM invocations for a single key`
      );
    }

    const iv = new Uint8Array(GCM_IV_LENGTH);
    new DataView(iv.buffer).setUint32(
      GCM_IV_LENGTH - Uint32Array.BYTES_PER_ELEMENT,
      this.nextInvocation
    );
    this.nextInvocation += 1;
    return iv;
  }
}
