// pulled from https://github.com/panva/dpop/tree/v1.4.1
// Modified to use CryptoService instead of crypto.subtle

import type {
  CryptoService,
  KeyPair,
  PrivateKey,
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
  privateKey: PrivateKey,
  cryptoService: CryptoService
) {
  const input = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(claimsSet)))}`;
  const signature = await cryptoService.sign(
    buf(input),
    privateKey,
    header.alg as AsymmetricSigningAlgorithm
  );
  return `${input}.${b64u(signature)}`;
}

const CHUNK_SIZE = 0x8000;
function encodeBase64Url(input: Uint8Array | ArrayBuffer) {
  const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : input;

  const arr = [];
  for (let i = 0; i < bytes.byteLength; i += CHUNK_SIZE) {
    arr.push(
      String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE) as unknown as number[])
    );
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
export type JWSAlgorithm = 'PS256' | 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'EdDSA';

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
  }
  switch (algorithm) {
    case 'ec:secp256r1':
      return 'ES256';
    case 'ec:secp384r1':
      return 'ES384';
    case 'ec:secp521r1':
      return 'ES512';
    default:
      throw new UnsupportedOperationError(`unsupported key algorithm: ${algorithm}`);
  }
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
 * @param keypair Opaque key pair
 * @param cryptoService CryptoService for cryptographic operations
 * @param htu The HTTP URI (without query and fragment parts) of the request
 * @param htm The HTTP method of the request
 * @param nonce Server-provided nonce.
 * @param accessToken Associated access token's value.
 * @param additional Any additional claims.
 */
export default async function DPoP(
  keypair: KeyPair,
  cryptoService: CryptoService,
  htu: string,
  htm: string,
  nonce?: string,
  accessToken?: string,
  additional?: Record<string, JsonValue>
): Promise<string> {
  const privateKey = keypair?.privateKey;
  const publicKey = keypair?.publicKey;

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

  // Detect algorithm from opaque key metadata
  const alg = determineJWSAlgorithmFromKeyInfo(publicKey.algorithm);

  // Export public key as JWK for the header
  const jwk = await cryptoService.exportPublicKeyJwk(publicKey);

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
