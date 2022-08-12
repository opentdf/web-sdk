import { createWriteStream } from 'fs';
import { buffer, text } from 'node:stream/consumers';
import DecoratedReadableStream from './DecoratedReadableStream';
import { toWebReadableStream } from 'web-streams-node';
import { Readable } from 'node:stream';

class NodeTdfStream extends DecoratedReadableStream {
  static convertToWebStream(stream: Readable) {
    return toWebReadableStream(stream);
  }

  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return {string} - the plaintext in string form.
   */
  async toString() {
    return await text(this.stream);
  }

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return {Buffer} - the plaintext in Buffer form.
   */
  async toBuffer() {
    return await NodeTdfStream.toBuffer(this.stream);
  }

  static async toBuffer(stream: Readable) {
    return await buffer(stream);
  }

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param {string} filepath - the path of the local file to write plaintext to.
   * @param {string} encoding - the charset encoding to use. Defaults to utf-8.
   */
  async toFile(filepath: string, encoding: BufferEncoding) {
    return new Promise<void>((resolve, reject) => {
      const file = createWriteStream(filepath, { encoding: encoding || 'utf-8', flags: 'w' });
      const reader = this.stream.getReader();
      const pump = () =>
        reader
          .read()
          .then((res: ReadableStreamDefaultReadResult<unknown>) => {
            if (res.done) {
              file.end();
              resolve();
            } else {
              file.write(res.value, encoding || 'utf-8', pump);
            }
          })
          .catch(reject);
      pump();
    });
  }
}

export default NodeTdfStream;
