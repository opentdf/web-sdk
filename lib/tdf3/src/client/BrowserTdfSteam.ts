import { DecoratedReadableStream } from './DecoratedReadableStream.js';
import streamSaver from 'streamsaver';
// @ts-ignore
import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils.js';

export class BrowserTdfStream extends DecoratedReadableStream {
  override async toFile(filepath = 'download.tdf'): Promise<void> {
    if (isFirefox()) {
      await fileSave(new Response(this.stream), {
        fileName: filepath,
        extensions: [`.${filepath.split('.').pop()}`],
      });
      return;
    }

    const fileStream = streamSaver.createWriteStream(filepath, {
      ...(this.contentLength && { size: this.contentLength }),
    });

    if (WritableStream) {
      return this.stream.pipeTo(fileStream);
    }

    // Write (pipe) manually
    const writer = fileStream.getWriter();
    const reader = this.stream.getReader();
    const pump = (): Promise<void> =>
      reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    pump();
  }
}
