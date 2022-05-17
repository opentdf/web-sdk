import { createWriteStream } from 'fs';
import {
  buffer,
  text,
} from 'node:stream/consumers';

const mixin = {
  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return {string} - the plaintext in string form.
   */
  async toString() {
    return await text(this);
  },

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return {Buffer} - the plaintext in Buffer form.
   */
  async toBuffer() {
    return await buffer(this);
  },

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param {string} filepath - the path of the local file to write plaintext to.
   * @param {string} encoding - the charset encoding to use. Defaults to utf-8.
   */
  async toFile(filepath, encoding) {
    return new Promise((resolve, reject) => {
      const file = createWriteStream(filepath, { encoding: encoding || 'utf-8', flag: 'w' });
      this.pipe(file);
      file.on('finish', () => {
        resolve();
      });
      file.on('error', reject);
    });
  }
}

export default mixin
