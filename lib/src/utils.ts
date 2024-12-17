import { exportSPKI, importX509 } from 'jose';

import { base64 } from './encodings/index.js';
import { pemCertToCrypto, pemPublicToCrypto } from './nanotdf-crypto/pemPublicToCrypto.js';
import { ConfigurationError } from './errors.js';

/**
 * Check to see if the given URL is 'secure'. This assumes:
 *
 * - `https` URLs are always secure
 * - `http` URLS are allowed for localhost
 * - And also for '`svc.cluster.local` and `.internal` URLs
 *
 * Note that this does not resolve the URL, so it is possible this could
 * resolve to some other internal URL, and may return `false` on non-fully
 * qualified internal URLs.
 *
 * @param url remote service to validate
 * @returns the url is local or `https`
 */
export function validateSecureUrl(url: string): boolean {
  const httpsRegex = /^https:/;
  if (/^http:\/\/(localhost|127\.0\.0\.1)(:[0-9]{1,5})?($|\/)/.test(url)) {
    console.warn(`Development URL detected: [${url}]`);
  } else if (
    /^http:\/\/([a-zA-Z.-]*[.])?svc\.cluster\.local($|\/)/.test(url) ||
    /^http:\/\/([a-zA-Z.-]*[.])?internal(:[0-9]{1,5})?($|\/)/.test(url)
  ) {
    console.info(`Internal URL detected: [${url}]`);
  } else if (!httpsRegex.test(url)) {
    console.error(`Insecure KAS URL loaded. Are you running in a secure environment? [${url}]`);
    return false;
  }
  return true;
}

export function padSlashToUrl(u: string): string {
  if (u.endsWith('/')) {
    return u;
  }
  return `${u}/`;
}

export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const rstrip = (str: string, suffix = ' '): string => {
  while (str && suffix && str.endsWith(suffix)) {
    str = str.slice(0, -suffix.length);
  }
  return str;
};

/**
 * Rough estimate of number of seconds to add to the current system clock time
 * to get the clock time on the given server, or origin if not specified
 * @param server a server to compute skew with
 * @returns the number of seconds to add to the current local system clock time
 * to get an rough guess of the time on the given server
 */
export const estimateSkew = async (serverEndpoint = window.origin): Promise<number> => {
  const localUnixTimeBefore = Date.now();
  const response = await fetch(serverEndpoint);
  return estimateSkewFromHeaders(response.headers, localUnixTimeBefore);
};

export type AnyHeaders = Headers;

/**
 * Rough estimate of number of seconds to add to the curren time to get
 * the clock time on the server that responded with the headers object.
 * @param headers A set of headers, which must include the `date` header
 * @param dateNowBefore time before initiating the request, usually by calling
 * `Date.now()`. Note this is in milliseconds since the epoch, while the
 * estimate is given in seconds.
 * @returns the number of seconds to add to the current local system clock time
 * to get an rough guess of the time on the server that was used
 */
export const estimateSkewFromHeaders = (headers: AnyHeaders, dateNowBefore?: number): number => {
  const localUnixTimeBefore = (dateNowBefore || Date.now()) / 1000;
  const serverDateString = headers.get('Date');
  if (serverDateString === null) {
    throw Error('Cannot get access to Date header!');
  }
  const serverUnixTime = Date.parse(serverDateString) / 1000;
  const localUnixTimeAfter = Date.now() / 1000;
  const deltaBefore = serverUnixTime - localUnixTimeBefore;
  const deltaAfter = serverUnixTime - localUnixTimeAfter;

  return Math.round((deltaBefore + deltaAfter) / 2);
};

export function addNewLines(str: string): string {
  if (!str) {
    return str;
  }
  let inputString = str;
  let finalString = '';
  while (inputString.length > 0) {
    finalString += inputString.substring(0, 64) + '\r\n';
    inputString = inputString.substring(64);
  }
  return finalString;
}

export async function cryptoPublicToPem(publicKey: CryptoKey): Promise<string> {
  if (publicKey.type !== 'public') {
    throw new ConfigurationError('incorrect key type');
  }

  const exportedPublicKey = await crypto.subtle.exportKey('spki', publicKey);
  const b64 = base64.encodeArrayBuffer(exportedPublicKey);
  const pem = addNewLines(b64);
  return `-----BEGIN PUBLIC KEY-----\r\n${pem}-----END PUBLIC KEY-----`;
}

export async function pemToCryptoPublicKey(pem: string): Promise<CryptoKey> {
  if (/-----BEGIN PUBLIC KEY-----/.test(pem)) {
    return pemPublicToCrypto(pem);
  } else if (/-----BEGIN CERTIFICATE-----/.test(pem)) {
    return pemCertToCrypto(pem);
  }
  // This can happen in several circumstances:
  // - When parsing a PEM key from a KAS server
  // - When converting between PEM and CryptoKey formats for user provided session keys (e.g. for DPoP)
  throw new TypeError(`unsupported pem type [${pem}]`);
}

export async function extractPemFromKeyString(keyString: string): Promise<string> {
  let pem: string = keyString;

  // Skip the public key extraction if we find that the KAS url provides a
  // PEM-encoded key instead of certificate
  if (keyString.includes('CERTIFICATE')) {
    const cert = await importX509(keyString, 'RS256', { extractable: true });
    pem = await exportSPKI(cert);
  }

  return pem;
}
