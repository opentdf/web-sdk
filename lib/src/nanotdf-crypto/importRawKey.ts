import { CipherType, KeyFormat, KeyUsageType } from './enums';
import getCryptoLib from './getCryptoLib';

/**
 * Import raw key
 *
 * A specific implementation of the importKey method to import raw keys. Specifies some defaults
 * to ensure security.
 *
 * @param key Key which needs to be imported
 * @param keyUsages How the key will be used
 * @param isExtractable Whether key is extractable
 */
export default async function importRawKey(
  key: ArrayBuffer,
  keyUsages: Array<KeyUsageType>,
  isExtractable = false
): Promise<CryptoKey> {
  const crypto = getCryptoLib();
  return crypto.importKey(KeyFormat.Raw, key, CipherType.AesGcm, isExtractable, keyUsages);
}
