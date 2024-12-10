import { TypedArray } from '../tdf/TypedArray.js';

export default function digest(
  hashType: AlgorithmIdentifier,
  data: TypedArray | ArrayBuffer
): Promise<ArrayBuffer> {
  return crypto.subtle.digest(hashType, data);
}
