/*
  The MockStream is just that; a "mocked" stream used by tdf3-js to read from/write to memory.

  This is meant as a stop-gap to allow for encrypting/decrypting data in the browser exclusively and without
  the use of URLs or files on disk. It works by mocking the called and emitted functions provided by Node.js
  streams, such that interactions between tdf3-js and the browser are seamless.
*/

export class MockStream {
  streamContent: Uint8Array[];
  totalBytes: number;
  readStreamEndCallback: () => void;
  writeStreamFinishCallback: () => void;
  dataCallback: (chunk: Uint8Array) => void;

  constructor(streamContent?: Uint8Array) {
    this.streamContent = streamContent ? [streamContent] : [];
    this.totalBytes = this.streamContent ? this.streamContent.length : 0;
  }

  readStreamData(callback: (data: Uint8Array) => void) {
    if (this.streamContent.length) {
      const rel = this.streamContent.pop();
      // relinquish a bit of data
      callback(rel);
      if (!this.streamContent.length) {
        this.readStreamEnd();
      }
    } else {
      this.readStreamEnd();
    }
  }

  /** In a read stream, 'end' is only emitted and not called */
  readStreamEnd() {
    this.readStreamEndCallback();
  }

  /** In a write stream, 'end' is called and not emitted */
  end(callback: () => void) {
    callback && process.nextTick(callback);
    this.writeStreamFinish();
  }

  writeStreamFinish() {
    this.writeStreamFinishCallback && this.writeStreamFinishCallback();
  }

  /** write a chunk of data (byte array) to memory, and call callback */
  write(chunk: Uint8Array, callback: () => void) {
    this.totalBytes += chunk.length;
    this.streamContent.push(chunk);
    callback && process.nextTick(callback);
    return true;
  }

  on(item: string, callback: () => void) {
    switch (item) {
      case 'data':
        this.dataCallback = callback;
        break;
      case 'end':
        // only start to process data when the end callback as been set
        this.readStreamEndCallback = callback;
        this.readStreamData(this.dataCallback);
        break;
      case 'finish':
        this.writeStreamFinishCallback = callback;
        break;
      case 'error':
        callback();
        break;
      case 'close':
        break;
      default:
        break;
    }
  }
}
