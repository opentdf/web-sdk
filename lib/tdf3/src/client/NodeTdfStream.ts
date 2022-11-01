import { createWriteStream } from 'fs';
import { DecoratedReadableStream } from './DecoratedReadableStream';

export class NodeTdfStream extends DecoratedReadableStream {
  override async toString() {
    return new Response(this.stream).text();
  }

  override async toBuffer() {
    const arrayBuffer = await new Response(this.stream).arrayBuffer();
    return Buffer.from(arrayBuffer);
  }

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param {string} filepath - the path of the local file to write plaintext to.
   * @param {string} encoding - the charset encoding to use. Defaults to utf-8.
   */
  async toFile(filepath: string, encoding: BufferEncoding = 'utf-8'): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = createWriteStream(filepath, { encoding, flags: 'w' });
      const reader = this.stream.getReader();
      const pump = () =>
        reader
          .read()
          .then((res) => {
            if (res.done) {
              file.end();
              resolve();
            } else {
              file.write(res.value, encoding, pump);
            }
          })
          .catch(reject);
      pump();
    });
  }
}
