import { DecoratedReadableStream, streamToBuffer } from './DecoratedReadableStream';
import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils';

export class BrowserTdfStream extends DecoratedReadableStream {
  override async toString(): Promise<string> {
    const results = await this.toBuffer();
    return results.toString('utf8');
  }

  override async toBuffer(): Promise<Buffer> {
    return await streamToBuffer(this.stream);
  }

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
