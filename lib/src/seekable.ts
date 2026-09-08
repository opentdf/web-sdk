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
      return fromBuffer(new Uint8Array(await new Response(location).arrayBuffer()));
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

/**
 * Converts a Source object to a ReadableStream.
 * @param source A Source object containing the type and location of the data.
 * Converts the source to a ReadableStream of Uint8Array.
 * This is useful for streaming data from various sources like files, remote URLs, or chunkers.
 * @returns A ReadableStream of Uint8Array.
 */
export async function sourceToStream(source: Source): Promise<ReadableStream<Uint8Array>> {
  switch (source.type) {
    case 'stream':
      return source.location;
    case 'file-browser':
      return source.location.stream();
    case 'chunker': {
      const chunkSize = 8 * 1024 * 1024; // 8 megabytes
      let offset = 0;
      return new ReadableStream({
        async pull(controller) {
          const chunk = await source.location(offset, offset + chunkSize);
          if (chunk.length === 0) {
            controller.close();
            return;
          }
          controller.enqueue(chunk);
          offset += chunk.length;
        },
      });
    }
    default: {
      const chunker = await fromSource(source);
      return new ReadableStream({
        async start(controller) {
          const chunk = await chunker();
          controller.enqueue(chunk);
          controller.close();
        },
      });
    }
  }
}

// Deprected name, prefer `fromSource`
export const fromDataSource = fromSource;

// Deprecated Name; prefer just `Source`
export type DataSource = Source;
