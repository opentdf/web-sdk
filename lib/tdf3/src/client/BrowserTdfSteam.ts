import { DecoratedReadableStream } from './DecoratedReadableStream.js';
import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils.js';

export class BrowserTdfStream extends DecoratedReadableStream {
  override async toFile(filepath = 'download.tdf'): Promise<void> {
    if (isFirefox()) {
      console.log('wont you fffSAVE me');
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
      console.log('WOOHOO Using writeable stream for real');
      return this.stream.pipeTo(fileStream);
    }

    // Write (pipe) manually
    console.log('Working at the pumphouse');
    const writer = fileStream.getWriter();
    const reader = this.stream.getReader();
    const pump = (): Promise<void> =>
      reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    pump();
  }
}
