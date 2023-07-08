import axios, { AxiosResponse } from 'axios';
import {
  type DecoratedReadableStream,
  isDecoratedReadableStream,
} from '../client/DecoratedReadableStream.js';

const axiosRemoteChunk = axios.create();

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

export const fromBuffer = (buffer: Uint8Array | Buffer): Chunker => {
  return (byteStart?: number, byteEnd?: number) => {
    return Promise.resolve(buffer.slice(byteStart, byteEnd));
  };
};

async function getRemoteChunk(url: string, range?: string): Promise<Uint8Array> {
  const res: AxiosResponse<Uint8Array> = await axiosRemoteChunk.get(url, {
    ...(range && {
      headers: {
        Range: `bytes=${range}`,
      },
    }),
    responseType: 'arraybuffer',
  });
  if (!res.data) {
    throw new Error('Unexpected response type: Server should have responded with an ArrayBuffer.');
  }
  return res.data;
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

export type DataSource =
  | { type: 'buffer'; location: Uint8Array }
  | { type: 'chunker'; location: Chunker }
  | { type: 'file-browser'; location: Blob }
  | { type: 'remote'; location: string }
  | { type: 'stream'; location: DecoratedReadableStream };

export const fromDataSource = async ({ type, location }: DataSource) => {
  switch (type) {
    case 'buffer':
      if (!(location instanceof Uint8Array)) {
        throw new Error('Invalid data source; must be uint8 array');
      }
      return fromBuffer(location);
    case 'chunker':
      if (!(location instanceof Function)) {
        throw new Error('Invalid data source; must be uint8 array');
      }
      return location;
    case 'file-browser':
      if (!(location instanceof Blob)) {
        throw new Error('Invalid data source; must be at least a Blob');
      }
      return fromBrowserFile(location);
    case 'remote':
      if (typeof location !== 'string') {
        throw new Error('Invalid data source; url not provided');
      }
      return fromUrl(location);
    case 'stream':
      if (!isDecoratedReadableStream(location)) {
        throw new Error('Invalid data source; must be DecoratedTdfStream');
      }
      return fromBuffer(await location.toBuffer());
    default:
      throw new Error(`Data source type not defined, or not supported: ${type}}`);
  }
};
