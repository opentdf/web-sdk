import { getChunkBuffer } from './chunks/getChunkBuffer.js';
import { getChunkStream } from './chunks/getChunkStream.js';
import { getDataReadable } from './chunks/getDataReadable.js';
import { getDataReadableStream } from './chunks/getDataReadableStream.js';
import { BodyDataTypes } from './types.js';

export const getChunk = (data: BodyDataTypes, partSize: number) => {
  if (data instanceof ArrayBuffer) {
    return getChunkBuffer(data, partSize);
  } else if (Object.prototype.hasOwnProperty.call(data, 'pipe')) {
    return getChunkStream<any>(data, partSize, getDataReadable);
  } else if (data instanceof Uint8Array) {
    return getChunkBuffer(data.buffer, partSize);
  } else if (data instanceof String || typeof data === 'string') {
    return getChunkBuffer(new TextEncoder().encode(data as string), partSize);
  }
  if (typeof (data as any).stream === 'function') {
    // approximate support for Blobs.
    return getChunkStream<ReadableStream>((data as any).stream(), partSize, getDataReadableStream);
  } else if (data instanceof ReadableStream) {
    return getChunkStream<ReadableStream>(data, partSize, getDataReadableStream);
  } else {
    throw new Error(
      'Body Data is unsupported format, expected data to be one of: string | Uint8Array | Readable | ReadableStream | Blob;.'
    );
  }
};
