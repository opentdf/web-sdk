import { type DecryptRange, DecryptRangeError } from '@opentdf/sdk';
import { CLIError } from './logger.js';

/**
 * Parses a byte count flag: a plain decimal integer that is a safe integer, so
 * offsets past 4 GiB are fine. Rejects signs, fractions, exponents and hex,
 * which `Number()` would otherwise accept or round.
 */
export function parseByteCount(name: string, value: unknown): number {
  const text = String(value).trim();
  const n = Number(text);
  if (!/^\d+$/.test(text) || !Number.isSafeInteger(n)) {
    throw new CLIError(
      'CRITICAL',
      `--${name} must be a non-negative integer of at most ${Number.MAX_SAFE_INTEGER}; got [${String(value)}]`
    );
  }
  return n;
}

/**
 * The plaintext range selected by `--offset` and `--length`, if either is set.
 * `--length` alone reads from the start; `--offset` alone reads to the end.
 */
export function rangeFromArgs({
  offset,
  length,
}: {
  offset?: unknown;
  length?: unknown;
}): DecryptRange | undefined {
  if (offset === undefined && length === undefined) {
    return undefined;
  }
  const range: DecryptRange = {
    offset: offset === undefined ? 0 : parseByteCount('offset', offset),
  };
  if (length !== undefined) {
    range.length = parseByteCount('length', length);
  }
  return range;
}

/**
 * Turns the SDK's error for an unsatisfiable or malformed range (such as an
 * offset past the end of the decrypted data) into a CLI error, which prints
 * just its message and exits with status 1. Other errors pass through
 * unchanged.
 */
export function asRangeCliError(e: unknown): unknown {
  return e instanceof DecryptRangeError ? new CLIError('CRITICAL', e.message, e) : e;
}

/** True for an `http:` or `https:` URL, which is read with HTTP Range requests. */
export function isUrl(location: string): boolean {
  return /^https?:\/\//i.test(location);
}
