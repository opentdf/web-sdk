import axios, { AxiosResponse } from 'axios';
import axiosRetry from 'axios-retry';
import { HttpsAgent } from 'agentkeepalive';
import { Buffer } from 'buffer';
import { createReadStream, readFile, statSync } from 'fs';
import { type AnyTdfStream, isAnyTdfStream } from '../client/tdf-stream.js';

const keepaliveAgent = new HttpsAgent({
  keepAlive: true,
  timeout: 10 * 60 * 1000,
  scheduling: 'fifo',
  maxSockets: 10
});

// const retry = axiosRetry.default;

axios.defaults.timeout = 10 * 60 * 1000; // 10 min
axios.defaults.httpsAgent = keepaliveAgent;
// @ts-ignore
axiosRetry(axios, { retries: 3 }); // Retries all idempotent requests (GET, HEAD, OPTIONS, PUT, DELETE)

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
  console.log('from buffer called');
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
        console.log('stream ended');
        resolve(Buffer.concat(buffers));
      });
    });
  };
};

export const fromUrl = (location: string): Chunker => {
  console.log('fromUrl url:', location);
  async function getRemoteChunk(url: string, range?: string): Promise<Uint8Array> {
    console.log('Called getRemoteChunk: ', range);
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
    console.log('Get remote chunk url:', location);
    console.log('Get remote chunk byteStart:', byteStart);
    console.log('Get remote chunk byteEnd:', byteEnd);
    if (byteStart === undefined) {
      return getRemoteChunk(location);
    }
    let rangeHeader = `${byteStart}`;
    if (byteEnd && byteEnd < 0) {
      // NOTE: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
      throw Error('negative end unsupported');
    } else {
      rangeHeader += `-${(byteEnd || 0) - 1}`;
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
      console.log('buffer data source detected');
      return fromBuffer(location);
    case 'file-browser':
      if (!(location instanceof Blob)) {
        throw new Error('Invalid data source; must be at least a Blob');
      }
      console.log('file-browser data source detected');
      return fromBrowserFile(location);
    case 'file-node':
      if (typeof location !== 'string') {
        throw new Error('Invalid data source; file path not provided');
      }
      console.log('file-node data source detected');
      return fromNodeFile(location);
    case 'remote':
      if (typeof location !== 'string') {
        throw new Error('Invalid data source; url not provided');
      }
      console.log('remote data source detected');
      return fromUrl(location);
    case 'stream':
      if (!isAnyTdfStream(location)) {
        throw new Error('Invalid data source; must be DecoratedTdfStream');
      }
      console.log('stream data source detected');
      return fromBuffer(await location.toBuffer());
    default:
      throw new Error(`Data source type not defined, or not supported: ${type}}`);
  }
};
