import { AwsCredentialIdentity, ChecksumConstructor, HashConstructor, SourceData } from "@aws-sdk/types";
import { toHex } from './hexCoding.js';

const MAX_CACHE_SIZE = 50;
const KEY_TYPE_IDENTIFIER = "aws4_request";
const signingKeyCache: Record<string, Uint8Array> = {};
const cacheQueue: Array<string> = [];

/**
 * Create a string describing the scope of credentials used to sign a request.
 *
 * @param shortDate The current calendar date in the form YYYYMMDD.
 * @param region    The AWS region in which the service resides.
 * @param service   The service to which the signed request is being sent.
 */
export const createScope = (shortDate: string, region: string, service: string): string =>
  `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`;

/**
 * Derive a signing key from its composite parts
 *
 * @param sha256Constructor A constructor function that can instantiate SHA-256
 *                          hash objects.
 * @param credentials       The credentials with which the request will be
 *                          signed.
 * @param shortDate         The current calendar date in the form YYYYMMDD.
 * @param region            The AWS region in which the service resides.
 * @param service           The service to which the signed request is being
 *                          sent.
 */
export const getSigningKey = async (
  sha256Constructor: ChecksumConstructor | HashConstructor,
  credentials: AwsCredentialIdentity,
  shortDate: string,
  region: string,
  service: string
): Promise<Uint8Array> => {
  const credsHash = await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId);
  const cacheKey = `${shortDate}:${region}:${service}:${toHex(credsHash)}:${credentials.sessionToken}`;
  if (cacheKey in signingKeyCache) {
    return signingKeyCache[cacheKey];
  }

  cacheQueue.push(cacheKey);
  while (cacheQueue.length > MAX_CACHE_SIZE) {
    delete signingKeyCache[cacheQueue.shift() as string];
  }

  let key: SourceData = `AWS4${credentials.secretAccessKey}`;
  for (const signable of [shortDate, region, service, KEY_TYPE_IDENTIFIER]) {
    key = await hmac(sha256Constructor, key, signable);
  }
  return (signingKeyCache[cacheKey] = key as Uint8Array);
};

const hmac = (
  ctor: ChecksumConstructor | HashConstructor,
  secret: SourceData,
  data: String
): Promise<Uint8Array> => {
  const hash = new ctor(secret);
  const buf = Buffer.from(data, 'utf8');
  const uint = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength / Uint8Array.BYTES_PER_ELEMENT);
  hash.update(uint);
  return hash.digest();
};
