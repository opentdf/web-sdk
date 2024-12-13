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

export const fromBuffer = (source: Uint8Array): Chunker => {
  return (byteStart?: number, byteEnd?: number) => {
    return Promise.resolve(source.slice(byteStart, byteEnd));
  };
};

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
      console.warn(`fetch failed with network error [${e}], retrying...`);
      sleep(2 ** i * 1000);
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
      // waits for 1, 2, 4 seconds
      sleep(2 ** i * 1000);
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
      throw new ConfigurationError(`Data source type not defined, or not supported: ${type}}`);
  }
};

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
