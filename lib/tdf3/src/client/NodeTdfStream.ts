import { createWriteStream } from 'node:fs';
import { Writable } from 'node:stream';
import {
  DecoratedStream,
  type DecoratedReadableStreamSinkOptions,
} from './DecoratedStream.js';

export class NodeTdfStream extends DecoratedStream {
  override async toFile(
    filepath: string,
    options: BufferEncoding | DecoratedReadableStreamSinkOptions = 'utf-8'
  ): Promise<void> {
    const encoding =
      (typeof options === 'string' && options) || (options && options.encoding) || 'utf-8';
    const nodeStream = createWriteStream(filepath, { encoding, flags: 'w', highWaterMark: 1 });
    const writer = Writable.toWeb(nodeStream);
    await this.readable.pipeTo(writer);
  }
}
