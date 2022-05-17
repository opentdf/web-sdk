const streamSaver = require('streamsaver');
import { WritableStream } from 'web-streams-polyfill/ponyfill';

const mixin = {
  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return {string} - the plaintext in string form.
   */
  async toString() {
    return await new Response(this).text();
  },

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return {Buffer} - the plaintext in Buffer form.
   */
  async toBuffer() {
    return Buffer.from(await new Response(this).arrayBuffer())
  },

  /**
   * Dump the stream content to a local file. This will consume the stream.
   *
   * @param {string} filepath - the path of the local file to write plaintext to.
   * @param {string} encoding - the charset encoding to use. Defaults to utf-8.
   */
  async toFile(filepath, encoding) {
    try {
      new streamSaver.WritableStream();
    } catch (e) {
      // Conditionally add ponyfill for Firefox
      streamSaver.WritableStream = WritableStream;
    }

    const fileName = filepath || 'download.tdf';

    const fileStream = streamSaver.createWriteStream(fileName, {
      ...(this.contentLength && { size: this.contentLength }),
    });

    if (WritableStream && this.pipeTo) {
      return this.pipeTo(fileStream);
    }

    // Write (pipe) manually
    const writer = fileStream.getWriter();
    const reader = this.getReader();
    const pump = () =>
      reader
        .read()
        .then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    pump();
  }
}

export default mixin
