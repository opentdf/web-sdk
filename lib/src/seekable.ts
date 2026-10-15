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

type RemoteChunk = { data: Uint8Array; totalLength?: number };

function safeLength(value: string | null): number | undefined {
  if (!value || !/^\d+$/.test(value)) {
    return undefined;
  }
  const length = Number(value);
  return Number.isSafeInteger(length) ? length : undefined;
}

async function getRemoteChunk(url: string, range?: string): Promise<RemoteChunk> {
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
    const contentRange = res.headers.get('Content-Range');
    const totalLength =
      res.status === 200
        ? data.byteLength
        : safeLength(/^bytes \d+-\d+\/(\d+)$/i.exec(contentRange ?? '')?.[1] ?? null);
    return { data: new Uint8Array(data), totalLength };
  }
  throw new AggregateError(errors, 'fetch failed after 3 retries');
}

export const fromUrl = async (location: string): Promise<Chunker> => {
  await Promise.resolve();
  let knownLength: number | undefined;
  let suffixRead = false;
  let headAttempted = false;
  return async (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    if (byteStart === undefined) {
      const chunk = await getRemoteChunk(location);
      knownLength = chunk.totalLength;
      return chunk.data;
    }
    // ZIP readers start with a suffix read. Learn the archive length from that
    // response before using offsets supplied by the archive in later requests.
    // Cross-origin responses hide Content-Range unless the server exposes it, so
    // fall back to a single HEAD. That is best effort: presigned GET URLs and some
    // servers reject HEAD, and ZipReader still bounds entry data and rejects short
    // reads without a known length.
    if (byteStart >= 0 && suffixRead && knownLength === undefined && !headAttempted) {
      headAttempted = true;
      try {
        const head = await fetch(location, { method: 'HEAD', redirect: 'follow' });
        if (head.ok) {
          knownLength = safeLength(head.headers.get('Content-Length'));
        }
      } catch {
        // Leave the length unknown; the range request below surfaces real failures.
      }
    }
    if (
      byteStart >= 0 &&
      knownLength !== undefined &&
      (byteStart >= knownLength || (byteEnd !== undefined && byteEnd > knownLength))
    ) {
      throw new InvalidFileError(
        `byte range [${byteStart}, ${byteEnd ?? 'end'}) extends past remote file length [${knownLength}]`
      );
    }
    let rangeHeader = `${byteStart}`;
    if (byteEnd && byteEnd < 0) {
      // NOTE: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
      throw Error('negative end unsupported');
    } else if (byteEnd) {
      rangeHeader += `-${byteEnd - 1}`;
    }
    const chunk = await getRemoteChunk(location, rangeHeader);
    knownLength = chunk.totalLength ?? knownLength;
    if (byteStart < 0) {
      suffixRead = true;
      if (knownLength === undefined && chunk.data.length < -byteStart) {
        knownLength = chunk.data.length;
      }
    }
    return chunk.data;
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
