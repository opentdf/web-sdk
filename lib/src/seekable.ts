import { ConfigurationError, InvalidFileError, NetworkError } from './errors.js';

/**
 * Read data from a seekable stream.
 * This is an abstraction for URLs with range queries and local file objects.
 * @param byteStart First byte to read. If negative, reads from the end. If absent, reads everything
 * @param byteEnd Index after last byte to read (exclusive)
 */
export type Chunker = (byteStart?: number, byteEnd?: number) => Promise<Uint8Array>;

/**
 * Type union for a variety of inputs.
 *
 * Not all of these scale equally, and the difference is inherent rather than a
 * missing optimization:
 *
 * - `'chunker'`, `'file-browser'` and `'remote'` are seekable. They stream in
 *   bounded pieces on both the encrypt and decrypt paths, and are the only
 *   types suitable for very large payloads.
 * - `'buffer'` is entirely in memory by construction. There is nothing to
 *   stream, so it is bounded by whatever the caller could already allocate.
 * - `'stream'` is single-pass, and zip needs random access -- the central
 *   directory is at the *end* of the archive. Decrypting one therefore requires
 *   buffering it whole; see {@link MAX_BUFFERED_STREAM_BYTES}. Encrypting from
 *   one is fine, since encryption is a forward pass.
 */
export type Source =
  | { type: 'buffer'; location: Uint8Array }
  | { type: 'chunker'; location: Chunker }
  | { type: 'file-browser'; location: Blob }
  | { type: 'remote'; location: string }
  | { type: 'stream'; location: ReadableStream<Uint8Array> };

/**
 * Creates a seekable object from a browser file object.
 * @param fileRef the browser file data
 */
export const fromBrowserFile = (fileRef: Blob): Chunker => {
  return async (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    if (byteStart === undefined) {
      return new Uint8Array(await fileRef.arrayBuffer());
    }
    const chunkBlob = fileRef.slice(byteStart, byteEnd);
    const arrayBuffer = await new Response(chunkBlob).arrayBuffer();
    return new Uint8Array(arrayBuffer);
  };
};

/**
 * Creates a seekable object from a buffer.
 * @param source A Uint8Array to read from.
 * If byteStart and byteEnd are not provided, reads the entire array.
 * If byteStart is provided, reads from that index to the end of the array.
 * If byteEnd is provided, reads from byteStart to byteEnd (exclusive).
 * If both byteStart and byteEnd are provided, reads from byteStart to byteEnd (exclusive).
 * @returns A promise that resolves to a Uint8Array containing the requested data.
 */
export const fromBuffer = (source: Uint8Array): Chunker => {
  return (byteStart?: number, byteEnd?: number) => {
    return Promise.resolve(source.slice(byteStart, byteEnd));
  };
};

/**
 * Creates a seekable object from a string.
 * @param source A string to read from.
 * If byteStart and byteEnd are not provided, reads the entire string.
 * If byteStart is provided, reads from that index to the end of the string.
 * If byteEnd is provided, reads from byteStart to byteEnd (exclusive).
 * If both byteStart and byteEnd are provided, reads from byteStart to byteEnd (exclusive).
 * @returns A promise that resolves to a Uint8Array containing the requested data.
 */
export const fromString = (source: string): Chunker => {
  return fromBuffer(new TextEncoder().encode(source));
};

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getRemoteChunk(url: string, range?: string): Promise<Uint8Array> {
  // loop with fetch for three times, with an exponential backoff
  // if the fetch fails with a network error
  // this is to handle transient network errors
  const errors: Error[] = [];
  for (let i = 0; i < 3; i++) {
    let res: Response;
    try {
      res = await fetch(url, {
        redirect: 'follow', // manual, *follow, error
        ...(range && {
          headers: {
            Range: `bytes=${range}`,
          },
        }),
      });
    } catch (e) {
      console.warn(`fetch failed with network error [${String(e)}], retrying...`);
      errors.push(e instanceof Error ? e : new Error(String(e)));
      await sleep(2 ** i * 1000);
      continue;
    }
    if (!res.ok) {
      if (res.status === 416) {
        throw new InvalidFileError(
          `${res.status}: range not satisfiable: requested [${range}] from [${url}]; response [${res.statusText}]`
        );
      } else if (res.status === 404) {
        throw new InvalidFileError(
          `${res.status}: [${url}] not found; response: [${res.statusText}]`
        );
      }
      console.warn(`fetch failed with status [${res.status}: ${res.statusText}], retrying...`);
      errors.push(new NetworkError(`${res.status}: ${res.statusText} for [${url}]`));
      // waits for 1, 2, 4 seconds
      await sleep(2 ** i * 1000);
      continue;
    }
    const data = await res.arrayBuffer();
    if (!data) {
      throw new NetworkError(
        `empty response for range request: requested [${range}] from [${url}]`
      );
    }
    return new Uint8Array(data);
  }
  throw new AggregateError(errors, 'fetch failed after 3 retries');
}

export const fromUrl = async (location: string): Promise<Chunker> => {
  await Promise.resolve();
  return async (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    if (byteStart === undefined) {
      return getRemoteChunk(location);
    }
    let rangeHeader = `${byteStart}`;
    if (byteEnd && byteEnd < 0) {
      // NOTE: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
      throw Error('negative end unsupported');
    } else if (byteEnd) {
      rangeHeader += `-${byteEnd - 1}`;
    }
    return await getRemoteChunk(location, rangeHeader);
  };
};

/**
 * Most a single-pass `'stream'` may weigh before it is refused.
 *
 * Making a `'stream'` seekable means holding all of it, because zip's central
 * directory is at the end of the archive; there is no in-place fix, only a
 * choice of failure. Refusing outright would break callers who pass small
 * streams that work fine today, so instead this bounds the damage: at 1 GiB the
 * SDK throws something actionable, naming the seekable source types, rather
 * than letting the tab reach the browser's own ~2 GiB `ArrayBuffer` wall and
 * die on an opaque allocation error.
 *
 * It is the *decrypt* path that needs this. Encrypting from a stream is a
 * forward pass and is not size-limited.
 */
export const MAX_BUFFERED_STREAM_BYTES = 1024 * 1024 * 1024;

/**
 * Drains a stream into one buffer, refusing partway through if it is too big.
 *
 * Counts as it goes rather than deferring to `Response.arrayBuffer()`, so a
 * 50 GB stream fails after `maxBytes`, not after 50 GB.
 */
export async function bufferStream(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number = MAX_BUFFERED_STREAM_BYTES
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.length;
      if (total > maxBytes) {
        throw new ConfigurationError(
          `Stream source is too large to make seekable: exceeds ${maxBytes.toLocaleString()}` +
            ` bytes. A zip archive must be read out of order, so a single-pass stream has to be` +
            ` buffered whole. Use a 'chunker', 'file-browser', or 'remote' source instead.`
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.length;
  }
  return buffer;
}

/**
 * Creates a seekable object from a source.
 * @param source A Source object containing the type and location of the data.
 * @returns A promise that resolves to a Chunker function.
 * @throws ConfigurationError if the source type is not supported or the location is invalid.
 */
export const fromSource = async ({ type, location }: Source): Promise<Chunker> => {
  switch (type) {
    case 'buffer':
      if (!(location instanceof Uint8Array)) {
        throw new ConfigurationError('Invalid data source; must be uint8 array');
      }
      return fromBuffer(location);
    case 'chunker':
      if (!(location instanceof Function)) {
        throw new ConfigurationError('Invalid data source; must be uint8 array');
      }
      return location;
    case 'file-browser':
      if (!(location instanceof Blob)) {
        throw new ConfigurationError('Invalid data source; must be at least a Blob');
      }
      return fromBrowserFile(location);
    case 'remote':
      if (typeof location !== 'string') {
        throw new ConfigurationError('Invalid data source; url not provided');
      }
      return fromUrl(location);
    case 'stream':
      return fromBuffer(await bufferStream(location));
    default:
      throw new ConfigurationError(
        `Data source type not defined, or not supported: ${String(type)}}`
      );
  }
};

/**
 * Length of a source in bytes, when it can be learned without reading it.
 *
 * Used to reject an over-budget encrypt before any bytes are processed, and to
 * pick a segment size that keeps the manifest within its ceiling. Best effort
 * by design: `undefined` means "unknown", never "empty", and every caller has
 * to stay correct without it. A `'chunker'` exposes no length, and a
 * `'stream'`'s is unknowable without draining it.
 *
 * For `'remote'` this costs one extra request. `HEAD` is tried first; when that
 * is unavailable or hidden by CORS, a one-byte range request is used to read
 * the total out of `Content-Range`. Any failure yields `undefined` rather than
 * throwing, since a size probe must not be able to fail an otherwise valid
 * encrypt.
 */
export async function sourceSize(source: Source): Promise<number | undefined> {
  switch (source.type) {
    case 'buffer':
      return source.location.byteLength;
    case 'file-browser':
      return source.location.size;
    case 'remote':
      return remoteSize(source.location);
    default:
      return undefined;
  }
}

async function remoteSize(url: string): Promise<number | undefined> {
  try {
    const head = await fetch(url, { method: 'HEAD', redirect: 'follow' });
    const contentLength = head.ok && head.headers.get('Content-Length');
    if (contentLength) {
      const size = Number.parseInt(contentLength, 10);
      if (Number.isSafeInteger(size) && size >= 0) {
        return size;
      }
    }
  } catch {
    // fall through to the range probe
  }
  try {
    const probe = await fetch(url, { redirect: 'follow', headers: { Range: 'bytes=0-0' } });
    // "bytes 0-0/1234"; a "*" total means the server does not know either.
    const total = probe.headers.get('Content-Range')?.split('/')[1];
    if (total && total !== '*') {
      const size = Number.parseInt(total, 10);
      if (Number.isSafeInteger(size) && size >= 0) {
        return size;
      }
    }
  } catch {
    // unknown size; callers fall back to the end-of-stream checks
  }
  return undefined;
}

/** Bytes requested per pull when reading a seekable source as a stream. */
export const STREAM_CHUNK_SIZE = 8 * 1024 * 1024;

/**
 * Reads a seekable source one bounded piece at a time.
 *
 * When `totalSize` is known the loop stops at it, which matters for `'remote'`:
 * a range request past the end of an object is a 416, so running off the end to
 * discover it would turn a clean finish into an error. Without a length it
 * falls back to reading until a pull comes back empty, which is all a bare
 * `Chunker` can tell us.
 *
 * A server that ignores `Range` and returns the whole body still produces the
 * right bytes -- the first pull satisfies the whole length and the stream
 * closes -- it just does not get the memory benefit.
 */
function seekableStream(chunker: Chunker, totalSize?: number): ReadableStream<Uint8Array> {
  let offset = 0;
  return new ReadableStream({
    async pull(controller) {
      if (totalSize !== undefined && offset >= totalSize) {
        controller.close();
        return;
      }
      const end =
        totalSize === undefined
          ? offset + STREAM_CHUNK_SIZE
          : Math.min(offset + STREAM_CHUNK_SIZE, totalSize);
      const chunk = await chunker(offset, end);
      if (chunk.length === 0) {
        if (totalSize !== undefined && offset < totalSize) {
          // Silently closing here would truncate the payload and produce a
          // short TDF that looks valid.
          throw new NetworkError(
            `source returned no bytes at offset ${offset} of ${totalSize}; read was truncated`
          );
        }
        controller.close();
        return;
      }
      controller.enqueue(chunk);
      offset += chunk.length;
    },
  });
}

/**
 * Converts a Source object to a ReadableStream.
 * @param source A Source object containing the type and location of the data.
 * Converts the source to a ReadableStream of Uint8Array.
 * This is useful for streaming data from various sources like files, remote URLs, or chunkers.
 * @param knownSize the source's length, when the caller already learned it via
 * {@link sourceSize}. Passing it avoids a second probe request for `'remote'`.
 * @returns A ReadableStream of Uint8Array.
 */
export async function sourceToStream(
  source: Source,
  knownSize?: number
): Promise<ReadableStream<Uint8Array>> {
  switch (source.type) {
    case 'stream':
      return source.location;
    case 'file-browser':
      return source.location.stream();
    case 'chunker':
      return seekableStream(source.location);
    case 'remote': {
      const size = knownSize ?? (await sourceSize(source));
      if (size === undefined) {
        // No length and no range support to infer one from: nothing to do but
        // what this always did, and take the whole object into memory.
        break;
      }
      return seekableStream(await fromSource(source), size);
    }
  }
  const chunker = await fromSource(source);
  return new ReadableStream({
    async start(controller) {
      const chunk = await chunker();
      controller.enqueue(chunk);
      controller.close();
    },
  });
}

// Deprected name, prefer `fromSource`
export const fromDataSource = fromSource;

// Deprecated Name; prefer just `Source`
export type DataSource = Source;
