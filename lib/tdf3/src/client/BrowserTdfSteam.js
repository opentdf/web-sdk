import ReadableStream from './DecoratedReadableStream';
import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';

class BrowserTdfStream extends ReadableStream {
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

  static async toBuffer(stream) {
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
  async toFile(filepath) {
    const fileName = filepath || 'download.tdf';

    const isFirefox = typeof InstallTrigger !== 'undefined';

    if (isFirefox) {
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
    const pump = () =>
      reader
        .read()
        .then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    pump();
  }
}

export default BrowserTdfStream;
