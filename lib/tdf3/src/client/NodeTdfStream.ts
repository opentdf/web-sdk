import { createWriteStream, PathLike } from 'fs';
import { buffer, text } from 'node:stream/consumers';
import { DecoratedReadableStream } from './DecoratedReadableStream';
import { toWebReadableStream } from 'web-streams-node';
import { Readable } from 'stream';

class NodeTdfStream extends DecoratedReadableStream {
  static convertToWebStream(stream: unknown): ReadableStream {
    return toWebReadableStream(stream);
  }

  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return {string} - the plaintext in string form.
   */
  async toString() {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return await text(this as any);
  }

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return {Buffer} - the plaintext in Buffer form.
   */
  async toBuffer() {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return await NodeTdfStream.toBuffer(this as any);
  }

  static async toBuffer(stream: NodeJS.ReadableStream | Readable) {
    return await buffer(stream);
  }

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param {string} filepath - the path of the local file to write plaintext to.
   * @param {string} encoding - the charset encoding to use. Defaults to utf-8.
   */
  async toFile(filepath: PathLike, encoding: any) {
    return new Promise((resolve: (value: void) => void, reject) => {
      const file = createWriteStream(filepath, { encoding: encoding || 'utf-8', flags: 'w' });
      const reader = this.getReader();
      const pump = () =>
        reader
          .read()
          .then((res) => {
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
