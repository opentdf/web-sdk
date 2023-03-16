import { Buffer } from 'buffer';
import { createReadStream, readFile, statSync } from 'fs';
import { type AnyTdfStream, isAnyTdfStream } from '../client/tdf-stream.js';

/**
 * Read data from a seekable stream.
 * @param byteStart First byte to read. If negative, reads from the end. If absent, reads everything
 * @param byteEnd Index after last byte to read (exclusive)
 */
export type Chunker = (byteStart?: number, byteEnd?: number) => Promise<Uint8Array>;

export const fromBrowserFile = (fileRef: Blob): Chunker => {
  return async (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    const chunkBlob = fileRef.slice(byteStart, byteEnd);
    const arrayBuffer = await new Response(chunkBlob).arrayBuffer();
    return new Uint8Array(arrayBuffer);
  };
};

export const fromBuffer = (buffer: Uint8Array): Chunker => {
  return (byteStart?: number, byteEnd?: number) => {
    return Promise.resolve(buffer.slice(byteStart, byteEnd));
  };
};

export const fromNodeFile = (filePath: string): Chunker => {
  const fileSize = statSync(filePath).size;

  return (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    let start = byteStart || 0;
    let end = byteEnd;

    if (!start && !end) {
      return new Promise<Uint8Array>((resolve, reject) => {
        readFile(filePath, (err: any | null, data: Uint8Array | PromiseLike<Uint8Array>) => {
          if (err) {
            reject(err);
          } else {
            resolve(data);
          }
        });
      });
    }
    if (start < 0) {
      // max with 0 for the case where the chunk size is larger than the file size.
      start = Math.max(0, fileSize - Math.abs(start));
    }
    if (byteEnd) {
      if (byteEnd < 0) {
        end = fileSize + byteEnd - 1;
      } else {
        end = byteEnd - 1;
      }
    }

    const rs = createReadStream(filePath, { start, end });
    const buffers: Uint8Array[] = [];
    return new Promise<Uint8Array>((resolve, reject) => {
      rs.on('data', (buff) => {
        if (typeof buff === 'string') {
          throw new Error('Incorrect read stream');
        }
        buffers.push(buff);
      });
      rs.on('error', reject);
      rs.on('end', () => {
        resolve(Buffer.concat(buffers));
      });
    });
  };
};

async function getRemoteChunk(url: string, range?: string): Promise<Uint8Array> {
  try {
    const res = await fetch(url, {
      ...(range && {
          headers: {
            Range: `bytes=${range}`,
          },
      }),
    })
    if(!res.ok) {
      throw new Error(
        'Unexpected response type: Server should have responded with an ArrayBuffer.'
      );
    }

    return await res.arrayBuffer() as Uint8Array;
  } catch (e) {
    if (e && e.response && e.response.status === 416) {
      console.log('Warning: Range not satisfiable');
    }
    throw e;
  }
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
    return getRemoteChunk(location, rangeHeader);
  };
};

type sourcetype = 'buffer' | 'file-browser' | 'file-node' | 'remote' | 'stream';
type DataSource = {
  type: sourcetype;
  location: AnyTdfStream | Uint8Array | Blob | string;
};

export const fromDataSource = async ({ type, location }: DataSource) => {
  switch (type) {
    case 'buffer':
      if (!(location instanceof Uint8Array)) {
        throw new Error('Invalid data source; must be uint8 array');
      }
      return fromBuffer(location);
    case 'file-browser':
      if (!(location instanceof Blob)) {
        throw new Error('Invalid data source; must be at least a Blob');
      }
      return fromBrowserFile(location);
    case 'file-node':
      if (typeof location !== 'string') {
        throw new Error('Invalid data source; file path not provided');
      }
      return fromNodeFile(location);
    case 'remote':
      if (typeof location !== 'string') {
        throw new Error('Invalid data source; url not provided');
      }
      return fromUrl(location);
    case 'stream':
      if (!isAnyTdfStream(location)) {
        throw new Error('Invalid data source; must be DecoratedTdfStream');
      }
      return fromBuffer(await location.toBuffer());
    default:
      throw new Error(`Data source type not defined, or not supported: ${type}}`);
  }
};
