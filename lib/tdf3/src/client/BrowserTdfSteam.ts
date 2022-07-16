import { DecoratedReadableStream } from './DecoratedReadableStream';
import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';
import { isSafari, isFirefox } from '../../../src/utils';

class BrowserTdfStream extends DecoratedReadableStream {
  contentLength?: number;
  constructor(...props: any) {
    super(...props);
    // workaround for safari https://stackoverflow.com/questions/58471434/problem-extending-native-es6-classes-in-safari
    if (isSafari()) {
      Object.setPrototypeOf(this, BrowserTdfStream.prototype);
    }
  }

  static convertToWebStream() {
    throw new Error('Please use Web Streams in browser environment');
  }

  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return {string} - the plaintext in string form.
   */
  async toString() {
    const results = await this.toBuffer();
    return results.toString('utf8');
  }

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return {Buffer} - the plaintext in Buffer form.
   */
  async toBuffer() {
    return await BrowserTdfStream.toBuffer(this);
  }

  static async toBuffer(stream: ReadableStream) {
    const reader = stream.getReader();
    let accumulator = new Uint8Array();
    let done = false;

    while (!done) {
      const result = await reader.read();
      if (result.value) {
        const chunk = new Uint8Array(accumulator.byteLength + result.value.byteLength);
        chunk.set(new Uint8Array(accumulator), 0);
        chunk.set(new Uint8Array(result.value), accumulator.byteLength);
        accumulator = chunk;
      }
      done = result.done;
    }

    return Buffer.from(accumulator.buffer);
  }

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param {string} filepath - the path of the local file to write plaintext to.
   */
  async toFile(filepath: string) {
    const fileName = filepath || 'download.tdf';

    if (isFirefox()) {
      return await fileSave(new Response(this), {
        fileName: fileName,
        extensions: [`.${filepath.split('.').pop()}`],
      });
    }

    const fileStream = streamSaver.createWriteStream(fileName, {
      ...(this.contentLength && { size: this.contentLength }),
    });

    if (WritableStream) {
      return this.pipeTo(fileStream);
    }

    // Write (pipe) manually
    const writer = fileStream.getWriter();
    const reader = this.getReader();
    return new Promise((resolve: (value: void) => void, reject) => {
      function pump() {
        reader
          .read()
          .then((res) => {
            if (res.done) {
              writer.close();
              resolve();
              return;
            }
            writer.write(res.value).then(pump).catch(reject);
          })
          .catch((e) => {
            writer.close();
            reject(e);
          });
      }
      pump();
    });
  }
}

export default BrowserTdfStream;
