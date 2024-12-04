import { EventEmitter } from 'eventemitter3';
import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils.js';

import { type Metadata } from '../tdf.js';
import { type Manifest } from '../models/index.js';
import { ConfigurationError } from '../../../src/errors.js';

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
  ee: EventEmitter;
  on: EventEmitter['on'];
  emit: EventEmitter['emit'];
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
    this.ee = new EventEmitter();
    this.on = (...args) => this.ee.on(...args);
    this.emit = (...args) => this.ee.emit(...args);
  }

  async getMetadata() {
    return new Promise((resolve, reject) => {
      if (this.metadata) {
        resolve(this.metadata);
      } else {
        this.on('error', reject);
        this.on('rewrap', (rewrapResponse: Metadata) => {
          this.metadata = rewrapResponse;
          resolve(rewrapResponse);
        });
      }
    });
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

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param filepath The path of the local file to write plaintext to.
   * @param encoding The charset encoding to use. Defaults to utf-8.
   */
  async toFile(
    filepath = 'download.tdf',
    options?: BufferEncoding | DecoratedReadableStreamSinkOptions
  ): Promise<void> {
    if (options && typeof options === 'string') {
      throw new ConfigurationError('unsupported operation: Cannot set encoding in browser');
    }
    if (isFirefox()) {
      await fileSave(new Response(this.stream), {
        fileName: filepath,
        extensions: [`.${filepath.split('.').pop()}`],
      });
      return;
    }

    if (this.fileStreamServiceWorker) {
      streamSaver.mitm = this.fileStreamServiceWorker;
    }

    const fileStream = streamSaver.createWriteStream(filepath, {
      writableStrategy: { highWaterMark: 1 },
      readableStrategy: { highWaterMark: 1 },
    });

    if (WritableStream) {
      return this.stream.pipeTo(fileStream, options);
    }

    // Write (pipe) manually
    const reader = this.stream.getReader();
    const writer = fileStream.getWriter();
    const pump = async (): Promise<void> => {
      const res = await reader.read();

      if (res.done) {
        return await writer.close();
      } else {
        await writer.write(res.value);
        return pump();
      }
    };
    return pump();

    // const pump = (): Promise<void> =>
    //   reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    // pump();
  }
}

export function isDecoratedReadableStream(s: unknown): s is DecoratedReadableStream {
  return (
    typeof (s as DecoratedReadableStream)?.toBuffer !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toFile !== 'undefined' &&
    typeof (s as DecoratedReadableStream)?.toString !== 'undefined'
  );
}
