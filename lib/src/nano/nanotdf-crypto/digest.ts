import { TypedArray } from '../tdf';
import getCryptoLib from './getCryptoLib';

export default function digest(
  hashType: AlgorithmIdentifier,
  data: TypedArray | ArrayBuffer
): Promise<ArrayBuffer> {
  const crypto = getCryptoLib();

  return crypto.digest(hashType, data);
}
