import { PlaintextStream } from './tdf-stream';

/**
 * A {@link https://nodejs.org/api/stream.html#stream_class_stream_readable|Readable} stream implementation that exposes convenience methods for writing
 * TDF ciphertext to various locations like files and strings.
 * <pre>
 // Run an encrypt, which returns a TDFCiphertextStream.
 ciphertextStream = await client.encrypt(encryptParams);

 // TDFCiphertextStream exposes a progress event emitter when toRemoteStore() is called on it.
 tdfCiphertextStream.toRemoteStore(fileName);

 tdfCiphertextStream.on('httpUploadProgress', progress => {
   console.log(`Uploaded ${progress.loaded} bytes`);
 });

 // Write the TDF ciphertext to a local file.
 await stream.toFile("/tmp/plain.tdf");
   </pre>
 * @see Client#decrypt
 * @hideconstructor
 */

export class TDFCiphertextStream extends PlaintextStream {
  constructor(byteLimit) {
    // see: https://nodejs.org/api/stream.html#stream_buffering
    super(byteLimit);
  }
  // TODO: Support reading in through this as well (unify with tdv-navigator)?

  /**
   * Dump the stream content to a string. This will consume the stream.
   * @return {string} - the TDF ciphertext in string form, encoded as binary.
   */
  async toString() {
    return super.toString('binary');
  }

  /**
   * Dump the stream content to a buffer. This will consume the stream.
   * @return {Buffer} - the TDF ciphertext in Buffer form.
   */
  async toBuffer() {
    return super.toBuffer();
  }

  /**
   * Dump the stream content to a local file. This will consume the stream.
   * @param {string} filepath - the path of the local file to write TDF ciphertext to.
   */
  async toFile(filepath) {
    return super.toFile(filepath, 'binary');
  }
}
