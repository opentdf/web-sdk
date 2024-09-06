import { AlgorithmName} from './../nanotdf-crypto/enums.js'

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
      name: AlgorithmName.ECDSA,
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
  const isValid = await crypto.subtle.verify(
    {
      name: AlgorithmName.ECDSA,
      hash: { name: 'SHA-256' },
    },
    publicKey,
    signature,
    data
  );
  return isValid;
}

/**
 * Extracts the r and s values from a given ECDSA signature.
 *
 * @param {Uint8Array} signatureBytes - The raw ECDSA signature bytes.
 * @returns {{ r: Uint8Array; s: Uint8Array }} An object containing the r and s values as Uint8Arrays.
 * @throws {Error} If the validation of the signature fails.
 */
export function extractRSValuesFromSignature(signatureBytes: Uint8Array): { r: Uint8Array; s: Uint8Array } {
    // Split the raw signature into r and s values
    const halfLength = Math.floor(signatureBytes.length / 2);
    const rValue = signatureBytes.slice(0, halfLength);
    const sValue = signatureBytes.slice(halfLength);

    // Correct validation
    if (!concatAndCompareUint8Arrays(rValue, sValue, signatureBytes)) {
        throw new Error('Invalid ECDSA signature');
    }

    return {
        r: rValue,
        s: sValue
    };
}


function concatAndCompareUint8Arrays(arr1: Uint8Array, arr2: Uint8Array, arr3: Uint8Array): boolean {
    // Create a new Uint8Array with the combined length of arr1 and arr2
    const concatenated = new Uint8Array(arr1.length + arr2.length);
    
    // Copy arr1 and arr2 into the new array
    concatenated.set(arr1, 0);
    concatenated.set(arr2, arr1.length);
    
    // Check if the lengths are the same
    if (concatenated.length !== arr3.length) {
        return false;
    }
    
    // Compare each element
    for (let i = 0; i < concatenated.length; i++) {
        if (concatenated[i] !== arr3[i]) {
            return false;
        }
    }
    
    return true;
}
