import { createWriteStream } from 'node:fs';
import { DecoratedReadableStream } from './DecoratedReadableStream.js';

export class NodeTdfStream extends DecoratedReadableStream {
  override async toFile(filepath: string, encoding: BufferEncoding = 'utf-8'): Promise<void> {
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
