import { createWriteStream } from 'node:fs';
import { DecoratedReadableStream } from './DecoratedReadableStream.js';

export class NodeTdfStream extends DecoratedReadableStream {
  override async toFile(filepath: string, encoding: BufferEncoding = 'utf-8'): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = createWriteStream(filepath, { encoding, flags: 'w', highWaterMark: 1 });
      const reader = this.stream.getReader();

      const pump = async (): Promise<void> => {
        let res = await reader.read();

        if (res.done) {
          file.end();
          return;
        } else {
          file.write(res.value, encoding);
          return pump();
        }
      };
      return pump();
    });
  }
}
