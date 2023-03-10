import { createWriteStream } from 'node:fs';
import { Writable } from 'node:stream';
import { DecoratedReadableStream } from './DecoratedReadableStream.js';

export class NodeTdfStream extends DecoratedReadableStream {
  override async toFile(filepath: string, encoding: BufferEncoding = 'utf-8'): Promise<void> {
    const nodeStream = createWriteStream(filepath, { encoding, flags: 'w' });
    const writer = Writable.toWeb(nodeStream);
    await this.stream.pipeTo(writer);
  }
}
