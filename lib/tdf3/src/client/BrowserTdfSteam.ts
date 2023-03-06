import { DecoratedReadableStream } from './DecoratedReadableStream.js';
// import streamSaver from 'streamsaver';
import { fileSave } from 'browser-fs-access';
import { isFirefox } from '../../../src/utils.js';

// const sleep = (ms: number) => new Promise((r) => window.setTimeout(r, ms));

export class BrowserTdfStream extends DecoratedReadableStream {
  override async toFile(filepath = 'download.tdf'): Promise<void> {
    if (isFirefox()) {
      console.log('Firefox detected');
      await fileSave(new Response(this.stream), {
        fileName: filepath,
        extensions: [`.${filepath.split('.').pop()}`],
      });
      return;
    }

    // native file system attempt
    //@ts-ignore
    // const newHandle = await window.showSaveFilePicker();

    // // create a FileSystemWritableFileStream to write to
    // const writableStream = await newHandle.createWritable();

    // const reader = this.stream.getReader();
    // const pump = (): Promise<void> =>
    //   reader.read().then(async (res) => (res.done ? await writableStream.close() : await writableStream.write(res.value).then(pump)));
    // pump();

    // concatenate files attempt
    console.log('Using concatenation strategy');
    //@ts-ignore
    const fileHandle = await window.showSaveFilePicker();
    const reader = this.stream.getReader();

    while (true) {
      const { done, value } = await reader.read();
      let writeableStream = await fileHandle.createWritable({ keepExistingData: true });

      if (done) {
        await writeableStream.close();
        return;
      }

      let offset = (await fileHandle.getFile()).size;
      await writeableStream.seek(offset);
      await writeableStream.write({ type: 'write', data: value });
      // await writeableStream.close();
    }

    // sync file handler attempt
    // console.log('Using sync strategy');
    // //@ts-ignore
    // const fileHandle = await window.showSaveFilePicker();
    // const reader = this.stream.getReader();

    // const accessHandle = await fileHandle.createSyncAccessHandle();

    // while (true) {
    //   const { done, value } = await reader.read();
    //   // let writeableStream = await fileHandle.createWritable({ keepExistingData: true });

    //   if (done) {
    //     accessHandle.close();
    //     return;
    //   }

    //   let fileSize = accessHandle.getSize();
    //   await accessHandle.write(value, { at: fileSize });
    //   await accessHandle.flush();
    // }

    // Original code attempt
    // const fileStream = streamSaver.createWriteStream(filepath, {
    //   ...(this.contentLength && { size: this.contentLength }),
    //   writableStrategy: new ByteLengthQueuingStrategy({highWaterMark: 1}),
    //   readableStrategy: new ByteLengthQueuingStrategy({highWaterMark: 1}),
    // });

    // // if (WritableStream) {
    // //   console.log('Writable stream detected');
    // //   return this.stream.pipeTo(fileStream);
    // // }

    // console.log('Writable stream not detected');

    // // // Write (pipe) manually
    // const writer = fileStream.getWriter();
    // const reader = this.stream.getReader();

    // while (true) {
    //   const { done, value} = await reader.read();

    //   if (done) {
    //     writer.close();
    //     return;
    //   }

    //   writer.write(value);

    // }

    // const pump = (): Promise<void> =>
    //   reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    // pump();
  }
}
