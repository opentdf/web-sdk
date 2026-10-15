import { type FileHandle, open } from 'node:fs/promises';
import { type Chunker } from '@opentdf/sdk';

/**
 * Largest single `FileHandle.read` we issue. Node rejects reads longer than
 * 2^31-1 bytes, so larger ranges are read in a loop.
 */
const MAX_READ = 1 << 30;

/**
 * A {@link Chunker} over a local file, plus the means to release it.
 */
export type FileChunker = Chunker & {
  /** File size in bytes, taken from `fstat` when the file was opened. */
  readonly size: number;
  /** Closes the underlying file handle. Safe to call more than once. */
  close(): Promise<void>;
};

/**
 * Resolve chunker-style `[byteStart, byteEnd)` arguments against a known size,
 * using the same rules as `Uint8Array.prototype.slice`: negative values count
 * back from the end, and results are clamped to `[0, size]`.
 */
export function resolveRange(
  size: number,
  byteStart?: number,
  byteEnd?: number
): [start: number, end: number] {
  const clamp = (n: number) => Math.min(Math.max(n < 0 ? size + n : n, 0), size);
  const start = byteStart === undefined ? 0 : clamp(byteStart);
  const end = byteEnd === undefined ? size : clamp(byteEnd);
  return [start, Math.max(start, end)];
}

/**
 * Opens a local file for random access by explicit byte position.
 *
 * This exists because `fs.openAsBlob()` cannot be used for files of 4 GiB or
 * more: Node reports a file-backed Blob's `size` modulo 2^32, so `slice()`
 * with a negative offset (which the zip reader uses to find the central
 * directory) reads from the wrong place. See nodejs/node#66207 and DSPX-5160.
 *
 * `FileHandle.read` takes a numeric position, which is exact up to 2^53, so
 * this works for any file size the SDK can otherwise handle.
 *
 * The returned function can be passed as `{ type: 'chunker', location }` to
 * both decrypt (random access) and encrypt (read sequentially in chunks until
 * an empty chunk is returned). Call `close()` when finished.
 */
export async function openFileChunker(path: string): Promise<FileChunker> {
  const handle: FileHandle = await open(path, 'r');
  let size: number;
  let originalStats: Awaited<ReturnType<FileHandle['stat']>>;
  try {
    const stats = await handle.stat({ bigint: true });
    if (!stats.isFile()) {
      throw new Error(`not a regular file [${path}]`);
    }
    if (stats.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`file is too large to address safely [${path}]`);
    }
    size = Number(stats.size);
    originalStats = stats;
  } catch (e) {
    await handle.close();
    throw e;
  }
  let closed: Promise<void> | undefined;

  const assertUnchanged = async () => {
    const stats = await handle.stat({ bigint: true });
    if (
      stats.size !== originalStats.size ||
      stats.mtimeNs !== originalStats.mtimeNs ||
      stats.ctimeNs !== originalStats.ctimeNs
    ) {
      throw new Error(`file changed while reading [${path}]`);
    }
  };

  const chunker = async (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    if (closed) {
      throw new Error(`file is closed [${path}]`);
    }
    const [start, end] = resolveRange(size, byteStart, byteEnd);
    const buf = new Uint8Array(end - start);
    let filled = 0;
    while (filled < buf.length) {
      const length = Math.min(buf.length - filled, MAX_READ);
      const { bytesRead } = await handle.read(buf, filled, length, start + filled);
      if (bytesRead === 0) {
        throw new Error(`file changed while reading [${path}]`);
      }
      filled += bytesRead;
    }
    await assertUnchanged();
    return buf;
  };

  return Object.assign(chunker, {
    size,
    close: () => (closed ??= handle.close()),
  });
}
