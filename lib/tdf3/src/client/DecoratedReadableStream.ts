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

/**
 * Implements a mailbox type, where a sender can add one and only one value,
 * and a reciever gets a promise for that value. The promise resolves if the
 * value has already been set, or waits for a sender to set it.
 */
class Mailbox<T> {
  private beenSet = false;
  private value?: T;
  private rejection?: any;
  private resolve?: (value: T) => void;
  private reject?: (reason?: any) => void;
  private promise: Promise<T>;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }

  set(value: T): void {
    if (this.beenSet) {
      throw new Error('Mailbox already set');
    }
    this.beenSet = true;
    if (this.resolve) {
      this.resolve(value);
      delete this.resolve;
      delete this.reject;
    } else {
      this.value = value;
    }
  }

  get(): Promise<T> {
    if (this.value !== undefined) {
      return Promise.resolve(this.value);
    }
    if (this.rejection !== undefined) {
      return Promise.reject(this.rejection);
    }

    return this.promise;
  }

  fail(reason?: any): void {
    if (this.beenSet) {
      throw new Error('Mailbox already set');
    }
    this.beenSet = true;
    if (this.reject) {
      this.reject(reason);
      delete this.resolve;
      delete this.reject;
    } else {
      this.rejection = reason;
    }
  }
}

export class DecoratedReadableStream {
  KEK: null | string;
  algorithm: string;
  policyUuid?: string;
  tdfSize: number;
  fileSize: number | undefined;
  stream: ReadableStream<Uint8Array>;
  metadata?: Promise<Metadata>;
  manifest: Manifest;
  fileStreamServiceWorker?: string;
  mailbox: Mailbox<Metadata> = new Mailbox();

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
    return this.mailbox.get();
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
