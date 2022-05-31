import { toWebReadableStream } from 'web-streams-node';

export { ZipReader, readUInt64LE } from './zip-reader';
export { ZipWriter } from './zip-writer';
export { keySplit, keyMerge } from './keysplit';
import { PlaintextStream } from '../client/tdf-stream';
export * from './chunkers';

export function inBrowser(): boolean {
  return typeof window !== 'undefined';
}

// @ts-ignore
export async function streamToBuffer(stream) {
  return await PlaintextStream.toBuffer(
    stream instanceof ReadableStream ? stream : toWebReadableStream(stream)
  );
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
