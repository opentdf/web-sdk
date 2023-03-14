import { createWriteStream } from 'node:fs';
import { Writable } from 'node:stream';
import {
  DecoratedReadableStream,
  type DecoratedReadableStreamSinkOptions,
} from './DecoratedReadableStream.js';

export class NodeTdfStream extends DecoratedReadableStream {
  override async toFile(
    filepath: string,
    options: BufferEncoding | DecoratedReadableStreamSinkOptions = 'utf-8'
  ): Promise<void> {
    const encoding =
      (typeof options === 'string' && options) || (options && options.encoding) || 'utf-8';
    const nodeStream = createWriteStream(filepath, { encoding, flags: 'w' });
    const writer = Writable.toWeb(nodeStream);
    await this.stream.pipeTo(writer);
  }
}
