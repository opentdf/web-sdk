import {
  DecoratedReadableStream,
  type DecoratedReadableStreamSinkOptions,
} from './DecoratedReadableStream.js';
import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils.js';

export class BrowserTdfStream extends DecoratedReadableStream {
  override async toFile(
    filepath = 'download.tdf',
    options?: BufferEncoding | DecoratedReadableStreamSinkOptions
  ): Promise<void> {
    if (options && typeof options === 'string') {
      throw new Error('Unsupported Operation: Cannot set encoding in browser');
    }
    if (isFirefox()) {
      await fileSave(new Response(this.stream), {
        fileName: filepath,
        extensions: [`.${filepath.split('.').pop()}`],
      });
      return;
    }

    if (this.fileStreamServiceWorker) {
      streamSaver.mitm = this.fileStreamServiceWorker;
    }

    const fileStream = streamSaver.createWriteStream(filepath, {
      ...(this.contentLength && { size: this.contentLength }),
      writableStrategy: { highWaterMark: 1 },
      readableStrategy: { highWaterMark: 1 },
    });

    if (WritableStream) {
      return this.stream.pipeTo(fileStream, options);
    }

    // Write (pipe) manually
    const reader = this.stream.getReader();
    const writer = fileStream.getWriter();
    const pump = async (): Promise<void> => {
      const res = await reader.read();

      if (res.done) {
        return await writer.close();
      } else {
        await writer.write(res.value);
        return pump();
      }
    };
    return pump();

    // const pump = (): Promise<void> =>
    //   reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    // pump();
  }
}
