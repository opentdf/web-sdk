import { type Metadata } from '../tdf.js';
import { type Manifest } from '../models/index.js';

/**
 * Drain a stream with a reader rather than `new Response(stream).arrayBuffer()`.
 *
 * Chrome reports *any* error raised while it pulls a Response body as a bare
 * `TypeError: Failed to fetch`, discarding the original. That turns a decrypt
 * that failed its integrity check into something indistinguishable from a
 * dropped connection — precisely the distinction a caller needs to make. A
 * reader rejects with the error the stream was errored with, so `IntegrityError`
 * survives the trip.
 */
export async function streamToBuffer(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    chunks.push(value);
    length += value.length;
  }
  const accumulator = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    accumulator.set(chunk, offset);
    offset += chunk.length;
  }
  return accumulator;
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
  requiredObligations?: string[];

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
    // Buffer first, for the same reason `toBuffer` does: `Response.text()`
    // would mask an integrity failure as a network error.
    return new TextDecoder().decode(await streamToBuffer(this.stream));
  }

  /**
   * The fully qualified obligations required to be fulfilled on stream contents
   * are set as decoration during the decrypt flow.
   */
  obligations(): string[] {
    return this.requiredObligations ?? [];
  }
}

export function isDecoratedReadableStream(s: unknown): s is DecoratedReadableStream {
  return (
    typeof (s as DecoratedReadableStream)?.stream !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toBuffer !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toString !== 'undefined'
  );
}
