import { Stream } from 'stream';

export { ZipReader, readUInt64LE } from './zip-reader';
export { ZipWriter } from './zip-writer';
export { keySplit, keyMerge } from './keysplit';
export * from './chunkers';

/**
 * Tests if an object is reasonably a Stream object... Not perfect, but should be
 * good enough.
 *
 * This method is a bit unreliable and may need to be updated from time to time
 * if it doesn't work...  This broke recently on us when webpack changed their
 * NodeJS shim object hierarchy to not have {Stream} as the root...
 */
export function isStream(obj: unknown): obj is Stream {
  // Do an instanceof check as a shortcut, this should work from node
  const isInstanceOfStream = obj instanceof Stream;

  // Additionally test the object structure and if it has a pipe function, this should work
  // in the browser.
  return (
    isInstanceOfStream || (typeof obj === 'object' && typeof (obj as Stream).pipe === 'function')
  );
}

export function inBrowser(): boolean {
  return typeof window !== 'undefined';
}

export function base64ToBuffer(b64: string): Buffer | Uint8Array {
  return inBrowser() && atob
    ? Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
    : Buffer.from(b64, 'base64');
}

export function arrayBufferToBuffer(ab: ArrayBuffer): Buffer {
  const buf = Buffer.alloc(ab.byteLength);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    buf[i] = view[i];
  }
  return buf;
}

export function bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}
