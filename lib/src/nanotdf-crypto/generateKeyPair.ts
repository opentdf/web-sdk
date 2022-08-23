import { AlgorithmName, NamedCurve, KeyUsageType } from './enums';

interface GenerateKeyPairOptions {
  type: AlgorithmName.ECDH | AlgorithmName.ECDSA;
  curve: NamedCurve;
  keyUsages: Array<KeyUsageType>;
  isExtractable: boolean;
}

export default async function generateKeyPair(
  { type: name, curve: namedCurve, keyUsages, isExtractable }: GenerateKeyPairOptions = {
    type: AlgorithmName.ECDH,
    curve: NamedCurve.P256,
    keyUsages: [KeyUsageType.DeriveBits, KeyUsageType.DeriveKey],
    isExtractable: true,
  }
): Promise<CryptoKeyPair | never> {
  return await crypto.subtle.generateKey({ name, namedCurve }, isExtractable, keyUsages);
}
