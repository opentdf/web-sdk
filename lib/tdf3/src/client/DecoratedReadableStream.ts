import { type Metadata } from '../tdf.js';
import { type Manifest } from '../models/index.js';

export async function streamToBuffer(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const accumulator = await new Response(stream).arrayBuffer();
  return new Uint8Array(accumulator);
}

export type DecoratedReadableStreamSinkOptions = {
  encoding?: BufferEncoding;
  signal?: AbortSignal;
};

export class DecoratedReadableStream {
  KEK: null | string;
  algorithm: string;
  policyUuid?: string;
  tdfSize: number;
  fileSize: number | undefined;
  stream: ReadableStream<Uint8Array>;
  metadata?: Metadata;
  manifest: Manifest;
  fileStreamServiceWorker?: string;

  constructor(
    underlyingSource: UnderlyingSource & {
      fileStreamServiceWorker?: string;
    }
  ) {
    if (underlyingSource.fileStreamServiceWorker) {
      this.fileStreamServiceWorker = underlyingSource.fileStreamServiceWorker;
    }
    this.stream = new ReadableStream(underlyingSource, {
      highWaterMark: 1,
    }) as ReadableStream<Uint8Array>;
  }

  async getMetadata() {
    return this.metadata;
  }

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return the plaintext in Buffer form.
   */
  async toBuffer(): Promise<Uint8Array> {
    return streamToBuffer(this.stream);
  }

  /**
   * Dump the stream content to a string. This will consume the stream.
   * NOTE: This interprets the stream as utf-8 encoded text, and therefore
   * will mangle any binary streams, e.g. as produced by the `zip` encoding
   * format. It is intended for use with the `HTML` encoding format, or with
   * encrypted utf-8 text documents, such as HTML or XML documents. For other formats,
   * it will produce text with encoding errors in most circumstances.
   * @return the plaintext in string form, for decrypt, or the html as a string,
   * for encrypt.
   */
  async toString(): Promise<string> {
    return new Response(this.stream).text();
  }
}

export function isDecoratedReadableStream(s: unknown): s is DecoratedReadableStream {
  return (
    typeof (s as DecoratedReadableStream)?.stream !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toBuffer !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toString !== 'undefined'
  );
}
