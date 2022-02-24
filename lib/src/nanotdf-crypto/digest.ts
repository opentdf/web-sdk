import { TypedArray } from '../tdf/index.ts';

export default function digest(
  hashType: AlgorithmIdentifier,
  data: TypedArray | ArrayBuffer
): Promise<ArrayBuffer> {
  return crypto.subtle.digest(hashType, data);
}
