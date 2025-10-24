import { exportSPKI, importX509 } from 'jose';

import { base64 } from './encodings/index.js';
import { pemCertToCrypto, pemPublicToCrypto } from './nanotdf-crypto/pemPublicToCrypto.js';
import { ConfigurationError } from './errors.js';
import {
  RewrapResponse,
  PolicyRewrapResultSchema,
  KeyAccessRewrapResultSchema,
} from './platform/kas/kas_pb.js';
import { create } from '@bufbuild/protobuf';
import { ConnectError } from '@connectrpc/connect';

const REQUIRED_OBLIGATIONS_METADATA_KEY = 'X-Required-Obligations';

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

/**
 * Pads a URL with a trailing slash if it does not already have one.
 * This is useful for ensuring that URLs are in a consistent format.
 * @param u The URL to pad.
 * @returns The padded URL.
 */
export function padSlashToUrl(u: string): string {
  if (u.endsWith('/')) {
    return u;
  }
  return `${u}/`;
}

/**
 * Checks if the current environment is a browser.
 * This is useful for determining if certain APIs or features are available.
 * @returns true if running in a browser, false otherwise.
 */
export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

/**
 * Removes trailing characters from a string.
 * @param str The string to trim.
 * @param suffix The suffix to remove (default is a single space).
 * @returns The trimmed string.
 */
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

/**
 * Adds new lines to a string every 64 characters.
 * @param str A string to add new lines to.
 * This function takes a string and adds new lines every 64 characters.
 * If the string is empty or undefined, it returns the original string.
 * This is useful for formatting long strings, such as public keys or certificates,
 * to ensure they are properly formatted for PEM encoding.
 * @returns The formatted string with new lines added.
 */
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

/**
 * Creates a PEM-encoded string from a public key.
 * @param publicKey The public key to convert.
 * @returns A promise that resolves to a PEM-encoded string.
 */
export async function cryptoPublicToPem(publicKey: CryptoKey): Promise<string> {
  if (publicKey.type !== 'public') {
    throw new ConfigurationError('incorrect key type');
  }

  const exportedPublicKey = await crypto.subtle.exportKey('spki', publicKey);
  const b64 = base64.encodeArrayBuffer(exportedPublicKey);
  const pem = addNewLines(b64);
  return `-----BEGIN PUBLIC KEY-----\r\n${pem}-----END PUBLIC KEY-----`;
}

/**
 * Converts a PEM-encoded public key to a CryptoKey.
 * @param pem The PEM-encoded public key.
 * @returns A promise that resolves to a CryptoKey.
 */
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

/**
 * Extracts the PEM-encoded public key from a key string.
 * @param keyString A string containing a public key or certificate.
 * This function extracts the PEM-encoded public key from a given key string.
 * If the key string contains a certificate, it imports the certificate and exports
 * the public key in PEM format. If the key string is already in PEM format, it returns
 * the key string as is.
 * @returns A promise that resolves to a PEM-encoded public key.
 */
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

/**
 * Extracts the error message from an RPC catch error.
 * @param error An error object, typically from a network request.
 * This function extracts the error message from a ConnectError or a generic Error.
 * If the error is a ConnectError or a standard Error, it returns the message.
 * If the error is of an unknown type, it returns a default message indicating
 * that an unknown network error occurred.
 * @returns The extracted error message.
 */
export function extractRpcErrorMessage(error: unknown): string {
  if (error instanceof ConnectError || error instanceof Error) {
    return error.message;
  }
  return 'Unknown network error occurred';
}

/**
 * Converts a KAS endpoint URL to a platform URL.
 * @param endpoint The KAS endpoint URL to extract the platform URL from.
 * This function extracts the base URL from a KAS endpoint URL.
 * It removes any trailing slashes and specific path segments related to rewrap or kas.
 * This is useful for obtaining the base URL for further API requests.
 * @returns The base URL of the platform.
 */
export function getPlatformUrlFromKasEndpoint(endpoint: string): string {
  let result = endpoint || '';
  if (result.endsWith('/')) {
    result = rstrip(result, '/');
  }
  if (result.endsWith('/v2/rewrap')) {
    result = result.slice(0, -10);
  }
  if (result.endsWith('/kas')) {
    result = result.slice(0, -4);
  }
  return result;
}

/**
 * Retrieves the fully qualified Obligations (values) that must be fulfilled from a rewrap response.
 */
export function getRequiredObligationFQNs(response: RewrapResponse) {
  const requiredObligations = new Set<string>();

  // Loop through response key access object results, checking proto values/types for a metadata key
  // that matches the expected KAS-provided fulfillable obligations list.
  for (const resp of response.responses) {
    for (const result of resp.results) {
      if (!result.metadata.hasOwnProperty(REQUIRED_OBLIGATIONS_METADATA_KEY)) {
        continue;
      }
      const value = result.metadata[REQUIRED_OBLIGATIONS_METADATA_KEY];
      if (value?.kind.case !== 'listValue') {
        continue;
      }
      const obligations = value.kind.value.values;
      for (const obligation of obligations) {
        if (obligation.kind.case === 'stringValue') {
          requiredObligations.add(obligation.kind.value.toLowerCase());
        }
      }
    }
  }

  return [...requiredObligations.values()];
}

/**
 * Upgrades a RewrapResponse from v1 format to v2.
 */
export function upgradeRewrapResponseV1(response: RewrapResponse) {
  if (response.responses.length > 0) {
    return;
  }
  if (response.entityWrappedKey.length === 0) {
    return;
  }

  response.responses = [
    create(PolicyRewrapResultSchema, {
      policyId: 'policy',
      results: [
        create(KeyAccessRewrapResultSchema, {
          keyAccessObjectId: 'kao-0',
          status: 'permit',
          result: {
            case: 'kasWrappedKey',
            value: response.entityWrappedKey,
          },
        }),
      ],
    }),
  ];
}
