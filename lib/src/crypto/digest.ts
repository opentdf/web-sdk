import { toArrayBuffer } from './buffer.js';

export default function digest(
  hashType: AlgorithmIdentifier,
  data: ArrayBufferLike
): Promise<ArrayBuffer> {
  return crypto.subtle.digest(hashType, toArrayBuffer(new Uint8Array(data)));
}
