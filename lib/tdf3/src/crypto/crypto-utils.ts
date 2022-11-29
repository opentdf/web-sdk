import { importX509 } from 'jose';
import { base64 } from '../../../src/encodings';

/**
 * Validates a specified key size
 * @param size in bits requested
 * @param minSize in bits allowed
 */
export const isValidAsymmetricKeySize = (size: number | undefined, minSize?: number): boolean => {
  // No size specified is fine because the minSize will be used
  if (size === undefined) {
    return !!minSize;
  }

  if (typeof size !== 'number' || (minSize && size < minSize)) {
    return false;
  }

  return true;
};

/**
 * Format a base64 string representation of a key file
 * in PEM PKCS#8 format by adding a header and footer
 * and new lines.
 *
 * The PEM spec says to use <CR><LF> (\r\n) per
 * https://tools.ietf.org/html/rfc1421#section-4.3.2.2, but
 * many implementations use just \n, so this function
 * follows the convention over the spec.
 *
 * @param  base64KeyString input
 * @param  label header and footer label that identifies key type
 * @return formatted output
 */
export const formatAsPem = (base64KeyString: string, label: string): string => {
  let pemCert = `-----BEGIN ${label}-----\n`;
  let nextIndex = 0;
  while (nextIndex < base64KeyString.length) {
    if (nextIndex + 64 <= base64KeyString.length) {
      pemCert += `${base64KeyString.substr(nextIndex, 64)}\n`;
    } else {
      pemCert += `${base64KeyString.substr(nextIndex)}\n`;
    }
    nextIndex += 64;
  }
  pemCert += `-----END ${label}-----\n`;
  return pemCert;
};

export const rsaPemAsCryptoKey = async (pem: string): Promise<CryptoKey> => {
  const algoDomString = {
    name: 'RSA-OAEP',
    hash: {
      name: 'SHA-256',
    },
  };

  if (pem.includes('CERTIFICATE')) {
    // FIXME Must match hash size of public key. We can (probably) guess by
    // length? See: https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedImportParams
    return importX509(pem, 'RS256') as Promise<CryptoKey>;
  }

  // Web Crypto APIs don't work with PEM formatted strings
  const publicKey = removePemFormatting(pem);

  const keyBuffer = base64.decodeArrayBuffer(publicKey);
  try {
    return await crypto.subtle.importKey('spki', keyBuffer, algoDomString, false, ['encrypt']);
  } catch (e) {
    if (e.message && e.message.includes('ash')) {
      const legacyAlgoDomString = {
        name: 'RSA-OAEP',
        hash: {
          name: 'SHA-1',
        },
      };
      return await crypto.subtle.importKey('spki', keyBuffer, legacyAlgoDomString, false, [
        'encrypt',
      ]);
    }
    throw e;
  }
};

/**
 * Remove PEM formatting (new line characters and headers / footers)
 * from a PEM string
 *
 * @param  input - PEM formatted string
 * @return String with formatting removed
 */
export const removePemFormatting = (input: string): string => {
  const oneLiner = input.replace(/[\n\r]/g, '');
  return oneLiner.replace(
    /-----+(?:BEGIN|END)\s(?:RSA\s)?(?:PUBLIC|PRIVATE|CERTIFICATE)\sKEY-----+/g,
    ''
  );
};
