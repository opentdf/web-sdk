import axios, { AxiosResponse } from 'axios';
import { createReadStream, readFile, statSync } from 'fs';
import { Stream } from 'stream';

/**
 * Read data from a seekable stream.
 * @param byteStart First byte to read. If negative, reads from the end. If absent, reads everything
 * @param byteEnd Index after last byte to read (exclusive)
 */
export type chunker = (byteStart?: number, byteEnd?: number) => Promise<Uint8Array>;

export const fromBrowserFile = (fileRef: Blob): chunker => {
  return async (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    const chunkBlob = fileRef.slice(byteStart, byteEnd);
    const arrayBuffer = await new Response(chunkBlob).arrayBuffer();
    return new Uint8Array(arrayBuffer);
  };
};

export const fromBuffer = (buffer: Uint8Array): chunker => {
  return (byteStart?: number, byteEnd?: number) => {
    return Promise.resolve(buffer.slice(byteStart, byteEnd));
  };
};

export const fromNodeFile = (filePath: string): chunker => {
  const fileSize = statSync(filePath).size;

  return (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    let start = byteStart;
    let end = byteEnd;

    if (!byteStart && !byteEnd) {
      return new Promise<Uint8Array>((resolve, reject) => {
        readFile(filePath, (err, data) => {
          if (err) {
            reject(err);
          } else {
            resolve(data);
          }
        });
      });
    }

    if (byteStart < 0) {
      // max with 0 for the case where the chunk size is larger than the file size.
      start = Math.max(0, fileSize - Math.abs(byteStart));
    }
    if (byteEnd) {
      if (byteEnd < 0) {
        end = fileSize + byteEnd - 1;
      } else {
        end = byteEnd - 1;
      }
    }

    const rs = createReadStream(filePath, { start, end });
    const buffers = [];
    return new Promise<Uint8Array>((resolve, reject) => {
      rs.on('data', (buff) => {
        buffers.push(buff);
      });
      rs.on('error', reject);
      rs.on('end', () => {
        resolve(Buffer.concat(buffers));
      });
    });
  };
};

export const fromUrl = (location: string): chunker => {
  async function getRemoteChunk(url, range?): Promise<Uint8Array> {
    try {
      const res: AxiosResponse<Uint8Array> = await axios.get(url, {
        ...(range && {
          headers: {
            Range: `bytes=${range}`,
          },
        }),
        responseType: 'arraybuffer',
      });
      if (!res.data) {
        throw new Error(
          'Unexpected response type: Server should have responded with an ArrayBuffer.'
        );
      }
      return res.data;
    } catch (e) {
      if (e && e.response && e.response.status === 416) {
        console.log('Warning: Range not satisfiable');
      }
      throw e;
    }
  }

  return (byteStart?: number, byteEnd?: number): Promise<Uint8Array> => {
    if (byteStart === undefined) {
      return getRemoteChunk(location);
    }
    let rangeHeader = `${byteStart}`;
    if (byteEnd < 0) {
      // NOTE: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
      throw Error('negative end unsupported');
    } else {
      rangeHeader += `-${byteEnd - 1}`;
    }
    return getRemoteChunk(location, rangeHeader);
  };
};

/**
 * If provided a 'stream' type, dump it all into a buffer.
 * TODO: Introduce TDF stream implementation to allow reasonable chunking for this case.
 */
export async function streamToBuffer(stream: Stream): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const bufs = [];

    stream.on('data', (chunk) => bufs.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(bufs)));
    stream.on('error', reject);
  });
}

type sourcetype = 'buffer' | 'file-browser' | 'file-node' | 'remote' | 'stream';
type DataSource = {
  type: sourcetype;
  location: unknown;
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
      if (!(location instanceof Stream)) {
        throw new Error('Invalid data source; must be at least a Blob');
      }
      return fromBuffer(await streamToBuffer(location));
    default:
      throw new Error(`Data source type not defined, or not supported: ${type}}`);
  }
};
