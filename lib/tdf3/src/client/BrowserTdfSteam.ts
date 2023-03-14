import { DecoratedReadableStream } from './DecoratedReadableStream.js';
import streamSaver from 'streamsaver';
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

    // * native file system attempt
    // //@ts-ignore
    // const newHandle = await window.showSaveFilePicker();

    // const writableStream = await newHandle.createWritable();

    // const reader = this.stream.getReader();
    // const pump = async (): Promise<void> => {
    //   let res = await reader.read(); //.then(async (res) => (res.done ? await writableStream.close() : await writableStream.write(res.value).then(pump)));

    //   if(res.done) {
    //     await writableStream.close();
    //   }
    //   else {
    //     await writableStream.write(res.value);
    //     await pump();
    //   }
    // }

    // await pump();



    // * concatenate files attempt
    // console.log('Using concatenation strategy');
    // //@ts-ignore
    // const fileHandle = await window.showSaveFilePicker();
    // const reader = this.stream.getReader();

    // while (true) {
    //   const { done, value } = await reader.read();
    //   let writeableStream = await fileHandle.createWritable({ keepExistingData: true });

    //   if (done) {
    //     await writeableStream.close();
    //     return;
    //   }

    //   // let offset = (await fileHandle.getFile()).size;
    //   // await writeableStream.seek(offset);
    //   await writeableStream.write({ type: 'write', data: value });
    //   await writeableStream.close();
    // }



    // * web worker attempt
    // console.log('Web worker attempt');
    // function worker_function() {
    //   // all worker code here, runs in background thread
    //   let accessHandle: any;
    //   addEventListener("message", async (message) => {

    //     if (message.data.action === 'OPEN') {
    //       const root = await navigator.storage.getDirectory();
    //       const fileHandle = await root.getFileHandle("draft.txt", { create: true });
    //       // @ts-ignore
    //       accessHandle = await fileHandle.createSyncAccessHandle();
    //       postMessage(structuredClone({
    //         action: 'OPENED'
    //       }));
    //     }
    //     else if (message.data.action === 'WRITE') {
    //       // @ts-ignore
    //       const fileSize = accessHandle.getSize();

    //       // ! may be needed
    //       // const encoder = new TextEncoder();
    //       // const encodedMessage = encoder.encode(message.data.chunk);

    //       // @ts-ignore
    //       const bytesWritten = await accessHandle.write(message.data.chunk, { at: fileSize });
    //       // @ts-ignore
    //       accessHandle.flush();
    //       postMessage(structuredClone({
    //         action: 'WRITTEN'
    //       }));
    //     }
    //     else if (message.data.action === 'CLOSE') {
    //       // @ts-ignore
    //       accessHandle.close();
    //       postMessage(structuredClone({
    //         action: 'CLOSED',
    //       }));
    //     }



    //     postMessage(`Hi this is worker, thanks for the ${message.data.action} message.`);
    //     return;
    //   });
    // }

    // let worker = new Worker(URL.createObjectURL(new Blob(["("+worker_function.toString()+")()"], {type: 'text/javascript'})));

    // worker.postMessage(structuredClone({
    //   chunk: 'The Answer to the Ultimate Question of Life, The Universe, and Everything... 42',
    //   action: 'OPEN'
    // }));

    // worker.onmessage = async (e) => {
    //   console.log('Message received from worker: ', e.data);

    //   if (e.data.action === 'OPENED') {
    //     console.log('Service worker message:  file handle opened');
    //     await pump();
    //   } else if (e.data.action === 'WRITTEN') {
    //     console.log('Service worker message: chunk written');
    //     await pump();
    //   } else if (e.data.action === 'CLOSED') {
    //     console.log('Service worker message: file handle closed');
    //     // ! free worker resources
    //     // ! free reader
    //   }
    // }

    // const reader = this.stream.getReader();

    // const pump = async (): Promise<void> => {
    //   console.log('calling reader.read()');
    //   let { done, value } = await reader.read();

    //   if(done) {
    //     console.log('stream done');
    //     worker.postMessage(structuredClone({
    //       action: 'CLOSE'
    //     }));
    //     return;
    //   }

    //   console.log('chunk: ', value?.buffer);

    //   worker.postMessage(structuredClone({
    //     action: 'WRITE',
    //     chunk: value
    //   }));
    // }




    // * service worker attempt
    // if('serviceWorker' in navigator) {
    //   navigator.serviceWorker.register('./service-worker.js')
    //     .then( () => {
    //         console.log("Service Worker registered");
    //     })
    // }

    // const reader = this.stream.getReader();

    // if ('serviceWorker' in navigator) {
    //   console.log('Using service worker method');
    //   navigator.serviceWorker.register('./service-worker.js')
      // .then(function() {
      //     return navigator.serviceWorker.ready;
      // })
      // .then(function(reg) {
      //     console.log('Service Worker is ready', reg);
      //     reg.pushManager.subscribe({userVisibleOnly: true}).then(async function(sub) {



      //       // while (true) {
      //       //   const { done, value } = await reader.read();

      //       //   if (done) {
      //       //     // ! Send file complete message to service worker
      //       //     return;
      //       //   }

      //       //   // ! Send chunk to service worker
      //       //   console.log('endpoint:', sub.endpoint);
      //       //   reg?.active?.postMessage(JSON.stringify({ value }));
      //       //   console.log("Posted message");
      //       // }
      //       return;

      //     });
      // }).catch(function(error) {
      //     console.log('Error : ', error);
      // });
  // }

    // * original code
    const fileStream = streamSaver.createWriteStream(filepath, {
      ...(this.contentLength && { size: this.contentLength }),
      writableStrategy: { highWaterMark: 1 },
      readableStrategy: { highWaterMark: 1 },
    });

    // if (WritableStream) {
    //   console.log('Using pipe() method');
    //   return this.stream.pipeTo(fileStream);
    // }

    // Write (pipe) manually
    const reader = this.stream.getReader();
    let writer = fileStream.getWriter();
    const pump = async (): Promise<void> => {
      console.log('calling pull');
      let res = await reader.read(); //.then(async (res) => (res.done ? await writableStream.close() : await writableStream.write(res.value).then(pump)));

      if(res.done) {
        return await writer.close();
      }
      else {
        await writer.write(res.value);
        console.log('file system write complete');
        return pump();
      }
    }
    return pump();

    // const pump = (): Promise<void> =>
    //   reader.read().then((res) => (res.done ? writer.close() : writer.write(res.value).then(pump)));
    // pump();
  }
}
