import {
  type AsymmetricSigningAlgorithm,
  type CryptoService,
  type SigningAlgorithm,
} from './declarations.js';
import { base64 } from '../../../src/encodings/index.js';
import {
  decodeProtectedHeader as joseDecodeProtectedHeader,
  errors as joseErrors,
  type JWTHeaderParameters,
  type JWTPayload,
  type JWTVerifyOptions,
  type SignOptions,
} from 'jose';
import jwtClaimsSet from './jose/jwt-claims-set.js';
import validateCrit from './jose/validate-crit.js';

export type JwtHeader = JWTHeaderParameters & { alg: SigningAlgorithm };
export type JwtPayload = JWTPayload;

/**
 * Options for JWT signing. Matches jose SignOptions interface.
 */
export type SignJwtOptions = SignOptions;

/**
 * Options for JWT verification. Matches jose JWTVerifyOptions interface.
 * Combines signature verification options and JWT claim verification options.
 */
export type VerifyJwtOptions = Omit<JWTVerifyOptions, 'algorithms'> & {
  /**
   * A list of accepted JWS "alg" (Algorithm) Header Parameter values.
   * By default all algorithms supported by the CryptoService are allowed.
   * Unsecured JWTs ({ "alg": "none" }) are never accepted.
   */
  algorithms?: SigningAlgorithm[];
};

/**
 * Base64url encode data per RFC 4648 Section 5.
 * Uses URL-safe alphabet (- and _ instead of + and /) with no padding.
 * Exported for testing purposes.
 */
export function base64urlEncode(data: string | Uint8Array): string {
  if (typeof data === 'string') {
    // Encode string to base64url
    const bytes = new TextEncoder().encode(data);
    return base64.encodeArrayBuffer(bytes.buffer, true); // urlSafe = true
  } else {
    // Encode Uint8Array to base64url
    const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    return base64.encodeArrayBuffer(buffer, true); // urlSafe = true
  }
}

/**
 * Helper to convert base64url to standard base64 with padding.
 */
function base64urlToBase64(str: string): string {
  // Convert base64url to base64: replace - with +, _ with /
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  const padding = (4 - (b64.length % 4)) % 4;
  b64 += '='.repeat(padding);

  return b64;
}

/**
 * Base64url decode to Uint8Array per RFC 4648 Section 5.
 */
function base64urlDecodeBytes(str: string): Uint8Array {
  const b64 = base64urlToBase64(str);
  return new Uint8Array(base64.decodeArrayBuffer(b64));
}

/**
 * Decode the protected header from a JWT without verifying the signature.
 * Useful for inspecting the header to determine key type before verification.
 *
 * @param token - The JWT string
 * @returns The decoded header
 * @throws Error if the token is malformed or uses alg "none"
 */
export function decodeProtectedHeader(token: string): JwtHeader {
  return joseDecodeProtectedHeader(token) as JwtHeader;
}

/**
 * Sign a JWT using CryptoService. Replaces jose SignJWT.
 *
 * Implementation:
 * 1. Base64url encode header and payload as JSON
 * 2. Create signing input: `${headerB64}.${payloadB64}`
 * 3. Sign via cryptoService.sign() (asymmetric) or signSymmetric() (HS256)
 * 4. Return compact JWT: `${headerB64}.${payloadB64}.${signatureB64}`
 *
 * @param cryptoService - Crypto implementation to use
 * @param payload - JWT payload (claims)
 * @param key - PEM-encoded private key for asymmetric algorithms, or raw key bytes for HS256
 * @param header - JWT header (must include alg)
 * @param options - Optional signing options (e.g., crit header handling)
 * @returns Compact JWT string
 */
export async function signJwt(
  cryptoService: CryptoService,
  payload: JwtPayload,
  key: string | Uint8Array,
  header: JwtHeader,
  options?: SignJwtOptions
): Promise<string> {
  validateCrit(joseErrors.JWSInvalid, new Map([['b64', true]]), options?.crit, header, header);

  // Encode header and payload per RFC 7515
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));

  // Create signing input
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);

  // Sign via CryptoService - route based on algorithm
  let signature: Uint8Array;
  if (header.alg === 'HS256') {
    // Symmetric signing requires Uint8Array key
    if (typeof key === 'string') {
      throw new Error('HS256 requires a Uint8Array key, not a PEM string');
    }
    signature = await cryptoService.signSymmetric(signingInputBytes, key);
  } else {
    // Asymmetric signing requires PEM string
    if (typeof key !== 'string') {
      throw new Error(`${header.alg} requires a PEM string key, not Uint8Array`);
    }
    signature = await cryptoService.sign(
      signingInputBytes,
      key,
      header.alg as AsymmetricSigningAlgorithm
    );
  }

  // Return compact JWT
  return `${signingInput}.${base64urlEncode(signature)}`;
}

/**
 * Verify a JWT and return its contents. Replaces jose jwtVerify.
 *
 * Implementation:
 * 1. Split token into header.payload.signature
 * 2. Decode header, validate algorithm against allowlist
 * 3. Verify signature via cryptoService.verify() (asymmetric) or verifySymmetric() (HS256)
 * 4. Validate JWT claims (aud, iss, exp, nbf, etc.)
 * 5. Return decoded header and payload
 *
 * @param cryptoService - Crypto implementation to use
 * @param token - The JWT string to verify
 * @param key - PEM-encoded public key for asymmetric algorithms, or raw key bytes for HS256
 * @param options - Verification options including algorithm allowlist and claim validations
 * @throws Error if signature invalid, algorithm not in allowlist, claims invalid, or token malformed
 * @returns Decoded header and payload
 */
export async function verifyJwt(
  cryptoService: CryptoService,
  token: string,
  key: string | Uint8Array,
  options?: VerifyJwtOptions
): Promise<{ header: JwtHeader; payload: JwtPayload }> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new joseErrors.JWTInvalid('Invalid Token or Protected Header formatting');
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  // Decode and validate header
  const headerRaw = decodeProtectedHeader(token);
  if (typeof headerRaw.alg !== 'string' || !headerRaw.alg) {
    throw new joseErrors.JWTInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
  }
  if ((headerRaw.alg as string) === 'none') {
    throw new joseErrors.JWTInvalid('Invalid JWT: alg "none" not allowed');
  }

  // Validate algorithm is in allowlist if provided
  if (options?.algorithms && !options.algorithms.includes(headerRaw.alg as SigningAlgorithm)) {
    throw new joseErrors.JWTInvalid(`Invalid JWT: algorithm "${headerRaw.alg}" not in allowlist`);
  }

  const extensions = validateCrit(
    joseErrors.JWSInvalid,
    new Map([['b64', true]]),
    options?.crit,
    headerRaw,
    headerRaw
  );

  // Now we know it's a valid algorithm
  const header = headerRaw as JwtHeader;

  // Verify signature via CryptoService - route based on algorithm
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signature = base64urlDecodeBytes(signatureB64);

  let valid: boolean;
  if (header.alg === 'HS256') {
    // Symmetric verification requires Uint8Array key
    if (typeof key === 'string') {
      throw new Error('HS256 requires a Uint8Array key, not a PEM string');
    }
    valid = await cryptoService.verifySymmetric(signingInputBytes, signature, key);
  } else {
    // Asymmetric verification requires PEM string
    if (typeof key !== 'string') {
      throw new Error(`${header.alg} requires a PEM string key, not Uint8Array`);
    }
    valid = await cryptoService.verify(
      signingInputBytes,
      signature,
      key,
      header.alg as AsymmetricSigningAlgorithm
    );
  }

  if (!valid) {
    throw new joseErrors.JWTInvalid('Invalid JWT: signature verification failed');
  }

  if (extensions.has('b64') && (header as { b64?: boolean }).b64 === false) {
    throw new joseErrors.JWTInvalid('JWTs MUST NOT use unencoded payload');
  }

  // Decode payload and validate JWT claims
  const payloadBytes = base64urlDecodeBytes(payloadB64);
  const payload = jwtClaimsSet(header, payloadBytes, options) as JwtPayload;

  return { header, payload };
}
