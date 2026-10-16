import { open, stat } from 'node:fs/promises';
import { type Chunker, type PlaintextRange, PlaintextRangeError, type Source } from '@opentdf/sdk';
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
}): PlaintextRange | undefined {
  if (offset === undefined && length === undefined) {
    return undefined;
  }
  const range: PlaintextRange = {
    offset: offset === undefined ? 0 : parseByteCount('offset', offset),
  };
  if (length !== undefined) {
    range.length = parseByteCount('length', length);
  }
  return range;
}

/**
 * Turns the SDK's error for an unsatisfiable or malformed range (such as an
 * offset past the end of the plaintext) into a CLI error, which prints just
 * its message and exits with status 1. Other errors pass through unchanged.
 */
export function asRangeCliError(e: unknown): unknown {
  return e instanceof PlaintextRangeError ? new CLIError('CRITICAL', e.message, e) : e;
}

/**
 * Reads a local file with positioned reads, following `Chunker` semantics: no
 * start reads everything, a negative start is a suffix, and ranges are clamped
 * to the file. Unlike `fs.openAsBlob`, whose `size` wraps at 4 GiB on some Node
 * releases, this addresses files of any safe-integer size. The file is opened
 * per read, so there is no handle to close.
 */
export function fromLocalFile(path: string, size: number): Chunker {
  return async (byteStart?: number, byteEnd?: number) => {
    let start = byteStart ?? 0;
    if (start < 0) {
      start = Math.max(size + start, 0);
    }
    const end = Math.min(byteEnd ?? size, size);
    const length = Math.max(end - start, 0);
    const buffer = new Uint8Array(length);
    if (!length) {
      return buffer;
    }
    const handle = await open(path, 'r');
    try {
      let read = 0;
      while (read < length) {
        const { bytesRead } = await handle.read(buffer, read, length - read, start + read);
        if (!bytesRead) {
          // The file shrank under us; return what there is.
          return buffer.subarray(0, read);
        }
        read += bytesRead;
      }
      return buffer;
    } finally {
      await handle.close();
    }
  };
}

/** True for an `http:` or `https:` URL, which is read with HTTP Range requests. */
export function isUrl(location: string): boolean {
  return /^https?:\/\//i.test(location);
}

/**
 * The source for reading a TDF: a URL goes through `fromUrl` (ranged
 * requests), and a local file through positioned reads.
 */
export async function tdfSource(location: string): Promise<Source> {
  if (!location) {
    throw new CLIError('CRITICAL', 'Must specify file or pipe');
  }
  if (isUrl(location)) {
    return { type: 'remote', location };
  }
  let size: number;
  try {
    const stats = await stat(location);
    if (!stats.isFile()) {
      throw new Error('not a file');
    }
    size = stats.size;
  } catch (e) {
    throw new CLIError(
      'CRITICAL',
      `File is not accessable [${location}]`,
      e instanceof Error ? e : new Error(String(e))
    );
  }
  return { type: 'chunker', location: fromLocalFile(location, size) };
}
