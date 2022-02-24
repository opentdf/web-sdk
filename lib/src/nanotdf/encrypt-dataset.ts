import NanoTDF from './NanoTDF.ts';
import Header from './models/Header.ts';
import DefaultParams from './models/DefaultParams.ts';
import Payload from './models/Payload.ts';
import { getBitLength as authTagLengthForCipher } from './models/Ciphers.ts';
import TypedArray from '../tdf/TypedArray.ts';
import encrypt from '../nanotdf-crypto/encrypt.ts';

/**
 * Encrypt the plain data into nanotdf buffer
 *
 * @param symmetricKey Key to encrypt the payload
 * @param header NanoTDF header
 * @param iv IV to be used for encrypting the payload
 * @param data The data to be encrypted
 */
export default async function encryptDataset(
  symmetricKey: CryptoKey,
  header: Header,
  iv: Uint8Array,
  data: string | TypedArray | ArrayBuffer
): Promise<ArrayBuffer> {
  // Auth tag length for policy and payload
  const authTagLengthInBytes = authTagLengthForCipher(DefaultParams.symmetricCipher) / 8;

  // Encrypt the payload
  let payloadAsBuffer;
  if (typeof data === 'string') {
    payloadAsBuffer = new TextEncoder().encode(data);
  } else {
    payloadAsBuffer = data;
  }

  const encryptedPayload = await encrypt(
    symmetricKey,
    new Uint8Array(payloadAsBuffer),
    iv,
    authTagLengthInBytes * 8
  );

  // Create payload
  const payload = new Payload(
    iv.slice(-3),
    new Uint8Array(encryptedPayload.slice(0, -authTagLengthInBytes)),
    new Uint8Array(encryptedPayload.slice(-authTagLengthInBytes))
  );

  // Create a nanotdf.
  const nanoTDF = new NanoTDF(header, payload);

  return nanoTDF.toBuffer();
}
