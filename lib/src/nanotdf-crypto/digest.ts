import { TypedArray } from '../tdf/index';

export default function digest(
  hashType: AlgorithmIdentifier,
  data: TypedArray | ArrayBuffer
): Promise<ArrayBuffer> {
  return crypto.subtle.digest(hashType, data);
}
