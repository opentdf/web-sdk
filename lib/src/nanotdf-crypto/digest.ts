
export default function digest(
  hashType: AlgorithmIdentifier,
  data: ArrayBufferLike
): Promise<ArrayBuffer> {
  return crypto.subtle.digest(hashType, data);
}
