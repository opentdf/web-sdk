import { base64 } from '../../../src/encodings/index.js';
import { type AnyKeyPair, type PemKeyPair } from './declarations.js';
import { rsaPkcs1Sha256 } from './index.js';

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

/**
 * Remove PEM formatting (new line characters and headers / footers)
 * from a PEM string
 *
 * @param  input - PEM formatted string
 * @return String with formatting removed
 */
export const removePemFormatting = (input: string): string => {
  if (typeof input !== 'string') {
    console.error('Not a pem string', input);
    return input;
  }
  const oneLiner = input.replace(/[\n\r]/g, '');
  // https://www.rfc-editor.org/rfc/rfc7468#section-2
  return oneLiner.replace(
    /-----(?:BEGIN|END)\s(?:RSA\s)?(?:PUBLIC|PRIVATE|CERTIFICATE)\sKEY-----/g,
    ''
  );
};

const PEMRE =
  /-----BEGIN\s((?:RSA\s)?(?:PUBLIC\sKEY|PRIVATE\sKEY|CERTIFICATE))-----[\s0-9A-Za-z+/=]+-----END\s\1-----/;

export const isPemKeyPair = (i: AnyKeyPair): i is PemKeyPair => {
  const { privateKey, publicKey } = i;
  if (typeof privateKey !== 'string' || typeof publicKey !== 'string') {
    return false;
  }
  const privateMatch = PEMRE.exec(privateKey);
  if (!privateMatch || !privateMatch[1] || privateMatch[1].indexOf('PRIVATE KEY') < 0) {
    return false;
  }
  const publicMatch = PEMRE.exec(publicKey);
  if (!publicMatch || !publicMatch[1] || publicMatch[1].indexOf('PRIVATE') >= 0) {
    return false;
  }
  return true;
};

export const isCryptoKeyPair = (i: AnyKeyPair): i is CryptoKeyPair => {
  const { privateKey, publicKey } = i;
  if (typeof privateKey !== 'object' || typeof publicKey !== 'object') {
    return false;
  }
  if (!(privateKey instanceof CryptoKey) || !(publicKey instanceof CryptoKey)) {
    return false;
  }
  return privateKey.type === 'private' && publicKey.type === 'public';
};

export const toCryptoKeyPair = async (input: AnyKeyPair): Promise<CryptoKeyPair> => {
  if (isCryptoKeyPair(input)) {
    return input;
  }
  if (!isPemKeyPair(input)) {
    throw new Error('invalid keypair');
  }
  const k = [input.publicKey, input.privateKey]
    .map(removePemFormatting)
    .map((e) => base64.decodeArrayBuffer(e));
  const algorithm = rsaPkcs1Sha256();
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.importKey('spki', k[0], algorithm, true, ['verify']),
    crypto.subtle.importKey('pkcs8', k[1], algorithm, true, ['sign']),
  ]);
  return { privateKey, publicKey };
};
