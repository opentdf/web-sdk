import { AppIdAuthProvider, AuthProvider } from '../../../src/auth/auth.js';

export { ZipReader, readUInt64LE } from './zip-reader.js';
export { ZipWriter } from './zip-writer.js';
export { keySplit, keyMerge } from './keysplit.js';
export { streamToBuffer } from '../client/DecoratedReadableStream.js';
export * from './chunkers.js';

export function base64ToBuffer(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64).split(''), (c) => c.charCodeAt(0));
}

export function isAppIdProviderCheck(
  provider: AuthProvider | AppIdAuthProvider
): provider is AppIdAuthProvider {
  return (provider as AppIdAuthProvider)._getName !== undefined;
}
export function concatUint8(uint8Arrays: Uint8Array[]): Uint8Array {
  const newLength = uint8Arrays.reduce(
    (accumulator, currentValue) => accumulator + currentValue.length,
    0
  );
  const combinedUint8Array = new Uint8Array(newLength);

  let offset = 0;
  for (const uint8Array of uint8Arrays) {
    combinedUint8Array.set(uint8Array, offset);
    offset += uint8Array.length;
  }

  return combinedUint8Array;
}

export function readUInt32LE(uint8Array: Uint8Array, offset: number): number {
  return (
    (uint8Array[offset] |
      (uint8Array[offset + 1] << 8) |
      (uint8Array[offset + 2] << 16) |
      (uint8Array[offset + 3] << 24)) >>>
    0
  );
}

export function readUInt16LE(uint8Array: Uint8Array, offset: number): number {
  return uint8Array[offset] | (uint8Array[offset + 1] << 8);
}

export function readUInt32BE(arrayBuffer: ArrayBuffer, offset: number): number {
  const view = new DataView(arrayBuffer, offset, 4);
  return view.getUint32(0, false);
}

export function writeUInt16LE(uint8Array: Uint8Array, value: number, offset: number): void {
  uint8Array[offset] = value & 0xff;
  uint8Array[offset + 1] = (value >> 8) & 0xff;
}

export function writeUInt32LE(uint8Array: Uint8Array, value: number, offset: number): void {
  uint8Array[offset] = value & 0xff;
  uint8Array[offset + 1] = (value >> 8) & 0xff;
  uint8Array[offset + 2] = (value >> 16) & 0xff;
  uint8Array[offset + 3] = (value >> 24) & 0xff;
}

export function copyUint8Arr(
  source: Uint8Array,
  target: Uint8Array,
  targetStart: number = 0,
  sourceStart: number = 0,
  sourceEnd: number = source.length
): number {
  const length = Math.min(sourceEnd - sourceStart, target.length - targetStart);
  target.set(source.subarray(sourceStart, sourceStart + length), targetStart);
  return length;
}
