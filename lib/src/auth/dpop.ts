// pulled from https://github.com/panva/dpop/tree/v1.4.1
// Modified to use CryptoService instead of crypto.subtle

import type {
  CryptoService,
  PemKeyPair,
  AsymmetricSigningAlgorithm,
} from '../../tdf3/src/crypto/declarations.js';

export type JsonObject = { [Key in string]?: JsonValue };
export type JsonArray = JsonValue[];
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

const encoder = new TextEncoder();

function buf(input: string): Uint8Array {
  return encoder.encode(input);
}

interface DPoPJwtHeaderParameters {
  alg: JWSAlgorithm;
  typ: string;
  jwk: JsonWebKey;
}

/**
 * Minimal JWT sign() implementation using CryptoService.
 */
async function jwt(
  header: DPoPJwtHeaderParameters,
  claimsSet: Record<string, unknown>,
  privateKeyPem: string,
  cryptoService: CryptoService
) {
  const input = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(claimsSet)))}`;
  const signature = await cryptoService.sign(
    buf(input),
    privateKeyPem,
    header.alg as AsymmetricSigningAlgorithm
  );
  return `${input}.${b64u(signature)}`;
}

const CHUNK_SIZE = 0x8000;
function encodeBase64Url(input: Uint8Array | ArrayBuffer) {
  if (input instanceof ArrayBuffer) {
    input = new Uint8Array(input);
  }

  const arr = [];
  for (let i = 0; i < input.byteLength; i += CHUNK_SIZE) {
    // @ts-expect-error - Uint8Array is compatible with number[] for fromCharCode.apply
    arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)));
  }
  return btoa(arr.join('')).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64u(input: Uint8Array | ArrayBuffer) {
  return encodeBase64Url(input);
}

/**
 * Generates 32 random bytes and encodes them using base64url.
 */
async function randomBytes(cryptoService: CryptoService) {
  return b64u(await cryptoService.randomBytes(32));
}

/**
 * Supported JWS `alg` Algorithm identifiers.
 *
 * @example PS256 CryptoKey algorithm
 * ```ts
 * interface Ps256Algorithm extends RsaHashedKeyAlgorithm {
 *   name: 'RSA-PSS'
 *   hash: { name: 'SHA-256' }
 * }
 * ```
 *
 * @example CryptoKey algorithm for the `ES256` JWS Algorithm Identifier
 * ```ts
 * interface Es256Algorithm extends EcKeyAlgorithm {
 *   name: 'ECDSA'
 *   namedCurve: 'P-256'
 * }
 * ```
 *
 * @example CryptoKey algorithm for the `RS256` JWS Algorithm Identifier
 * ```ts
 * interface Rs256Algorithm extends RsaHashedKeyAlgorithm {
 *   name: 'RSASSA-PKCS1-v1_5'
 *   hash: { name: 'SHA-256' }
 * }
 * ```
 *
 * @example CryptoKey algorithm for the `EdDSA` JWS Algorithm Identifier (Experimental)
 *
 * Runtime support for this algorithm is very limited, it depends on the [Secure Curves in the Web
 * Cryptography API](https://wicg.github.io/webcrypto-secure-curves/) proposal which is yet to be
 * widely adopted. If the proposal changes this implementation will follow up with a minor release.
 *
 * ```ts
 * interface EdDSAAlgorithm extends KeyAlgorithm {
 *   name: 'Ed25519'
 * }
 * ```
 */
export type JWSAlgorithm = 'PS256' | 'ES256' | 'RS256' | 'EdDSA';

class UnsupportedOperationError extends Error {
  constructor(message?: string) {
    super(message ?? 'operation not supported');
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

/**
 * Determines a supported JWS `alg` identifier from PublicKeyInfo algorithm string.
 */
function determineJWSAlgorithmFromKeyInfo(algorithm: string): JWSAlgorithm {
  if (algorithm.startsWith('rsa:')) {
    return 'RS256';
  } else if (algorithm === 'ec:secp256r1') {
    return 'ES256';
  }
  throw new UnsupportedOperationError(`unsupported key algorithm: ${algorithm}`);
}

function isPemString(key: unknown): key is string {
  return typeof key === 'string' && key.includes('-----BEGIN');
}

/**
 * Returns the current unix timestamp in seconds.
 */
function epochTime() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Generates a unique DPoP Proof JWT.
 *
 * @param keypair PEM-encoded key pair
 * @param cryptoService CryptoService for cryptographic operations
 * @param htu The HTTP URI (without query and fragment parts) of the request
 * @param htm The HTTP method of the request
 * @param nonce Server-provided nonce.
 * @param accessToken Associated access token's value.
 * @param additional Any additional claims.
 */
export default async function DPoP(
  keypair: PemKeyPair,
  cryptoService: CryptoService,
  htu: string,
  htm: string,
  nonce?: string,
  accessToken?: string,
  additional?: Record<string, JsonValue>
): Promise<string> {
  const privateKey = keypair?.privateKey;
  const publicKey = keypair?.publicKey;

  if (!isPemString(privateKey)) {
    throw new TypeError('"keypair.privateKey" must be a PEM string');
  }

  if (!isPemString(publicKey)) {
    throw new TypeError('"keypair.publicKey" must be a PEM string');
  }

  if (typeof htu !== 'string') {
    throw new TypeError('"htu" must be a string');
  }

  if (typeof htm !== 'string') {
    throw new TypeError('"htm" must be a string');
  }

  if (nonce !== undefined && typeof nonce !== 'string') {
    throw new TypeError('"nonce" must be a string or undefined');
  }

  if (accessToken !== undefined && typeof accessToken !== 'string') {
    throw new TypeError('"accessToken" must be a string or undefined');
  }

  if (
    additional !== undefined &&
    (typeof additional !== 'object' || additional === null || Array.isArray(additional))
  ) {
    throw new TypeError('"additional" must be an object');
  }

  // Detect algorithm from public key using CryptoService
  const keyInfo = await cryptoService.importPublicKeyPem(publicKey);
  const alg = determineJWSAlgorithmFromKeyInfo(keyInfo.algorithm);

  // Get public key as JWK for the header
  const jwk = await cryptoService.pemToJwk(publicKey);

  // Compute access token hash if provided
  let ath: string | undefined;
  if (accessToken) {
    const athBytes = await cryptoService.digest('SHA-256', buf(accessToken));
    ath = b64u(athBytes);
  }

  return jwt(
    {
      alg,
      typ: 'dpop+jwt',
      jwk,
    },
    {
      ...additional,
      iat: epochTime(),
      jti: await randomBytes(cryptoService),
      htm,
      nonce,
      htu,
      ath,
    },
    privateKey,
    cryptoService
  );
}
