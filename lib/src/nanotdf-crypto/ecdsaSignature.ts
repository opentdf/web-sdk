/**
 * Computes an ECDSA signature for the given data using the provided private key.
 *
 * This function uses the Web Crypto API to generate a digital signature
 * for the input data using the ECDSA algorithm with SHA-256 as the hash function.
 *
 * @param {CryptoKey} privateKey - The ECDSA private key used for signing.
 * @param {Uint8Array} data - The data to be signed.
 * @returns {Promise<ArrayBuffer>} - A promise that resolves to the generated signature.
 */
export async function computeECDSASig(
  privateKey: CryptoKey,
  data: Uint8Array
): Promise<ArrayBuffer> {
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    privateKey,
    data
  );
  return signature;
}

/**
 * Verifies an ECDSA signature using the provided public key and data.
 *
 * This function uses the Web Crypto API to verify the digital signature
 * for the input data using the ECDSA algorithm with SHA-256 as the hash function.
 *
 * @param {CryptoKey} publicKey - The ECDSA public key used for verification.
 * @param {Uint8Array} signature - The signature to be verified.
 * @param {Uint8Array} data - The data that was signed.
 * @returns {Promise<boolean>} - A promise that resolves to a boolean indicating whether the signature is valid.
 */
export async function verifyECDSASignature(
  publicKey: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  const isValid = await window.crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    publicKey,
    signature,
    data
  );
  return isValid;
}

/**
 * Extracts the R and S components from an ECDSA signature in ASN.1 DER format.
 *
 * The signature is expected to be in the following format:
 * 0x30 | totalLength | 0x02 | r's length | r | 0x02 | s's length | s
 *
 * This function parses the signature and extracts the R and S components.
 *
 * @param {Uint8Array} signatureArray - The ECDSA signature in ASN.1 DER format.
 * @returns {{ r: Uint8Array, s: Uint8Array }} - An object containing the R and S components.
 */
export function extractRSValuesFromSignature(signatureArray: Uint8Array) {
  // The signature is in ASN.1 DER format
  // It should look like: 0x30 | totalLength | 0x02 | r's length | r | 0x02 | s's length | s

  // Skip the first byte (0x30)
  let index = 1;

  // Skip total length
  // Check if the length is encoded in (short form)1 or (long form)2 bytes, and skip accordingly
  // Short form: The most significant bit is always 0, if most significant bit of the
  //  current byte is set. It is long form.
  // Long form: The most significant bit is always 1, The rest of this byte (the lower 7 bits)
  // tells us how many additional bytes are used to encode the length.
  index += signatureArray[index] & 0x80 ? (signatureArray[index] & 0x7f) + 1 : 1;

  // Skip 0x02
  index++;

  // Get r's length
  const rLength = signatureArray[index];
  index++;

  // Extract r
  const r = signatureArray.slice(index, index + rLength);
  index += rLength;

  // Skip 0x02
  index++;

  // Get s's length
  const sLength = signatureArray[index];
  index++;

  // Extract s
  const s = signatureArray.slice(index, index + sLength);

  return { r, s };
}
