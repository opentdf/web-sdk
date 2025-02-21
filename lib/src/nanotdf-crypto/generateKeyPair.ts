import { AlgorithmName, NamedCurve } from './enums.js';

type Subset<K, T extends K> = T;

type GenerateKeyPairOptions = {
  type: AlgorithmName.ECDH | AlgorithmName.ECDSA;
  curve: NamedCurve;
  keyUsages: Array<KeyUsage>;
  isExtractable: boolean;
}

export async function generateKeyPair(
  { type: name, curve: namedCurve, keyUsages, isExtractable }: GenerateKeyPairOptions = {
    type: AlgorithmName.ECDH,
    curve: NamedCurve.P256,
    keyUsages: ['deriveBits', 'deriveKey'],
    isExtractable: true,
  }
): Promise<CryptoKeyPair | never> {
  return crypto.subtle.generateKey({ name, namedCurve }, isExtractable, keyUsages);
}
