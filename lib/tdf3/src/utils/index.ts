import { Buffer } from 'buffer';
import { AppIdAuthProvider, AuthProvider } from '../../../src/auth/auth.js';

export { ZipReader, readUInt64LE } from './zip-reader.js';
export { ZipWriter } from './zip-writer.js';
export { keySplit, keyMerge } from './keysplit.js';
export { streamToBuffer } from '../client/DecoratedReadableStream.js';
export * from './chunkers.js';

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

export function isAppIdProviderCheck(
  provider: AuthProvider | AppIdAuthProvider
): provider is AppIdAuthProvider {
  return (provider as AppIdAuthProvider)._getName !== undefined;
}

export function bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}
