import { decrypt as cryptoDecrypt } from '../nanotdf-crypto/index.js';
import type NanoTDF from './NanoTDF.js';

/**
 * Decrypt nanotdf with a crypto key
 *
 * @param key Crypto key used to decrypt nanotdf
 * @param nanotdf NanoTDF to decrypt
 */
export default async function decrypt(key: CryptoKey, nanotdf: NanoTDF): Promise<ArrayBuffer> {
  // console.log(`Decrypting for content: ${nanotdf}`, nanotdf.header.authTagLength);
  return await cryptoDecrypt(
    key,
    nanotdf.payload.ciphertextWithAuthTag,
    nanotdf.payload.iv,
    // Auth tag length in bits
    nanotdf.header.authTagLength
  );
}
