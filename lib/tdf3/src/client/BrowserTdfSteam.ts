import { DecoratedReadableStream } from './DecoratedReadableStream.js';
import streamSaver from 'streamsaver';
// import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils.js';

export class BrowserTdfStream extends DecoratedReadableStream {
  override async toFile(filepath = 'download.tdf'): Promise<void> {
    if (isFirefox()) {
      let ponyfill = await import('web-streams-polyfill');
      // @ts-ignore
      streamSaver.WritableStream = ponyfill.WritableStream;
    }

    const fileStream = streamSaver.createWriteStream(filepath, {
      ...(this.contentLength && { size: this.contentLength }),
      writableStrategy: { highWaterMark: 1 },
      readableStrategy: { highWaterMark: 1 },
    });

    if (WritableStream) {
      return this.stream.pipeTo(fileStream);
    }

    // Write (pipe) manually
    const reader = this.stream.getReader();
    let writer = fileStream.getWriter();
    const pump = async (): Promise<void> => {
      let res = await reader.read();

      if(res.done) {
        return await writer.close();
      }
      else {
        await writer.write(res.value);
        return pump();
      }
    }
    return pump();

    // const pump = (): Promise<void> =>
    //   reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    // pump();
  }
}
