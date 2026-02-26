import {
  type AsymmetricSigningAlgorithm,
  type CryptoService,
  type PrivateKey,
  type PublicKey,
  type SigningAlgorithm,
  type SymmetricKey,
} from './declarations.js';
import { base64 } from '../../../src/encodings/index.js';

export type JwtHeader = { alg: SigningAlgorithm; typ?: 'JWT'; [key: string]: unknown };
export type JwtPayload = { [key: string]: unknown };

/**
 * Options for JWT signing. Matches jose SignOptions interface.
 */
export interface SignJwtOptions {
  /**
   * An object with keys representing recognized "crit" (Critical) Header Parameter names.
   * The value for those is either `true` or `false`. `true` when the Header Parameter MUST
   * be integrity protected, `false` when it's irrelevant.
   */
  crit?: {
    [propName: string]: boolean;
  };
}

/**
 * Options for JWT verification. Matches jose JWTVerifyOptions interface.
 * Combines signature verification options and JWT claim verification options.
 */
export interface VerifyJwtOptions {
  /**
   * A list of accepted JWS "alg" (Algorithm) Header Parameter values.
   * By default all algorithms supported by the CryptoService are allowed.
   * Unsecured JWTs ({ "alg": "none" }) are never accepted.
   */
  algorithms?: SigningAlgorithm[];

  /**
   * An object with keys representing recognized "crit" (Critical) Header Parameter names.
   */
  crit?: {
    [propName: string]: boolean;
  };

  /**
   * Expected JWT "aud" (Audience) claim value(s).
   */
  audience?: string | string[];

  /**
   * Expected clock tolerance for time-based validations.
   * Can be a number (seconds) or a string with units: "30s", "5m", "1h", "1d".
   */
  clockTolerance?: string | number;

  /**
   * Expected JWT "iss" (Issuer) claim value(s).
   */
  issuer?: string | string[];

  /**
   * Maximum age of the token. Can be a number (seconds) or a string with units: "30s", "5m", "1h", "1d".
   */
  maxTokenAge?: string | number;

  /**
   * Expected JWT "sub" (Subject) claim value.
   */
  subject?: string;

  /**
   * Expected JWT "typ" header parameter value.
   */
  typ?: string;

  /**
   * Date to use for time-based validations (for testing).
   * Defaults to current time.
   */
  currentDate?: Date;

  /**
   * List of claim names that must be present in the JWT payload.
   */
  requiredClaims?: string[];
}

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
    return base64.encodeArrayBuffer(data.buffer, true); // urlSafe = true
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
 * Base64url decode to string per RFC 4648 Section 5.
 */
function base64urlDecode(str: string): string {
  const b64 = base64urlToBase64(str);
  const bytes = base64.decodeArrayBuffer(b64);
  return new TextDecoder().decode(bytes);
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
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: expected 3 parts');
  }
  const header = JSON.parse(base64urlDecode(parts[0])) as { alg: string; [key: string]: unknown };

  // Security: reject unsigned JWTs
  if (header.alg === 'none') {
    throw new Error('Invalid JWT: alg "none" not allowed');
  }

  return header as JwtHeader;
}

/**
 * Sign a JWT using CryptoService. Replaces jose SignJWT.
 *
 * Implementation:
 * 1. Base64url encode header and payload as JSON
 * 2. Create signing input: `${headerB64}.${payloadB64}`
 * 3. Sign via cryptoService.sign() (asymmetric) or hmac() (HS256)
 * 4. Return compact JWT: `${headerB64}.${payloadB64}.${signatureB64}`
 *
 * @param cryptoService - Crypto implementation to use
 * @param payload - JWT payload (claims)
 * @param key - For asymmetric (RS256, ES256): PrivateKey (opaque). For HS256: SymmetricKey (opaque).
 * @param header - JWT header (must include alg)
 * @param options - Optional signing options (e.g., crit header handling)
 * @returns Compact JWT string
 */
export async function signJwt(
  cryptoService: CryptoService,
  payload: JwtPayload,
  key: PrivateKey | SymmetricKey,
  header: JwtHeader,
  options?: SignJwtOptions
): Promise<string> {
  // Validate crit header if present (basic validation only)
  if (header.crit && options?.crit) {
    for (const critParam of header.crit as string[]) {
      if (!(critParam in options.crit)) {
        throw new Error(`Critical header parameter "${critParam}" is not recognized`);
      }
    }
  }

  // Encode header and payload per RFC 7515
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));

  // Create signing input
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);

  // Sign via CryptoService - route based on algorithm
  let signature: Uint8Array;
  if (header.alg === 'HS256') {
    if (key._brand !== 'SymmetricKey') {
      throw new Error('HS256 requires a SymmetricKey');
    }
    signature = await cryptoService.hmac(signingInputBytes, key);
  } else {
    if (key._brand !== 'PrivateKey') {
      throw new Error(`${header.alg} requires a PrivateKey`);
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
 * 3. Verify signature via cryptoService.verify() (asymmetric) or verifyHmac() (HS256)
 * 4. Validate JWT claims (aud, iss, exp, nbf, etc.)
 * 5. Return decoded header and payload
 *
 * @param cryptoService - Crypto implementation to use
 * @param token - The JWT string to verify
 * @param key - For asymmetric: PEM string or PublicKey (opaque). For HS256: Uint8Array or SymmetricKey (opaque).
 * @param options - Verification options including algorithm allowlist and claim validations
 * @throws Error if signature invalid, algorithm not in allowlist, claims invalid, or token malformed
 * @returns Decoded header and payload
 */
export async function verifyJwt(
  cryptoService: CryptoService,
  token: string,
  key: string | Uint8Array | PublicKey | SymmetricKey,
  options?: VerifyJwtOptions
): Promise<{ header: JwtHeader; payload: JwtPayload }> {
  // Decode and validate header (also rejects alg "none")
  const headerRaw = decodeProtectedHeader(token);

  // Validate algorithm is in allowlist if provided
  if (options?.algorithms && !options.algorithms.includes(headerRaw.alg as SigningAlgorithm)) {
    throw new Error(`Invalid JWT: algorithm "${headerRaw.alg}" not in allowlist`);
  }

  // Split token for signature verification
  const parts = token.split('.');
  const [headerB64, payloadB64, signatureB64] = parts;

  // Validate typ header if expected
  if (options?.typ && headerRaw.typ !== options.typ) {
    throw new Error(`Invalid JWT: unexpected "typ" header value "${headerRaw.typ}"`);
  }

  // Validate crit header if present
  if (headerRaw.crit && options?.crit) {
    for (const critParam of headerRaw.crit as string[]) {
      if (!(critParam in options.crit)) {
        throw new Error(`Critical header parameter "${critParam}" is not recognized`);
      }
    }
  }

  // Now we know it's a valid algorithm
  const header = headerRaw as JwtHeader;

  // Verify signature via CryptoService - route based on algorithm
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signature = base64urlDecodeBytes(signatureB64);

  let valid: boolean;
  if (header.alg === 'HS256') {
    // Symmetric verification - accept Uint8Array or SymmetricKey
    if (typeof key === 'string') {
      throw new Error('HS256 requires a Uint8Array or SymmetricKey, not a PEM string');
    }
    if ('_brand' in key && key._brand === 'PublicKey') {
      throw new Error('HS256 requires a SymmetricKey, not a PublicKey');
    }
    // Convert Uint8Array to SymmetricKey if needed, otherwise assume it's already SymmetricKey
    const symmetricKey =
      key instanceof Uint8Array
        ? await cryptoService.importSymmetricKey(key)
        : (key as SymmetricKey);
    valid = await cryptoService.verifyHmac(signingInputBytes, signature, symmetricKey);
  } else {
    // Asymmetric verification - accept string (PEM) or PublicKey
    if (key instanceof Uint8Array) {
      throw new Error(`${header.alg} requires a PEM string or PublicKey, not Uint8Array`);
    }
    if (typeof key === 'object' && '_brand' in key && key._brand === 'SymmetricKey') {
      throw new Error(`${header.alg} requires a PublicKey, not a SymmetricKey`);
    }
    // Convert PEM string to PublicKey if needed, otherwise assume it's already PublicKey
    const publicKey =
      typeof key === 'string'
        ? await cryptoService.importPublicKey(key, { usage: 'sign' })
        : (key as PublicKey);
    valid = await cryptoService.verify(
      signingInputBytes,
      signature,
      publicKey,
      header.alg as AsymmetricSigningAlgorithm
    );
  }

  if (!valid) {
    throw new Error('Invalid JWT: signature verification failed');
  }

  // Decode payload
  const payload = JSON.parse(base64urlDecode(payloadB64)) as JwtPayload;

  // Validate JWT claims
  validateJwtClaims(payload, options);

  return { header, payload };
}

/**
 * Helper function to parse time duration strings like "5m", "1h" to seconds.
 */
function parseDuration(duration: string | number): number {
  if (typeof duration === 'number') {
    return duration;
  }

  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(`Invalid duration format: "${duration}"`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 3600;
    case 'd':
      return value * 86400;
    default:
      throw new Error(`Unknown duration unit: "${unit}"`);
  }
}

/**
 * Validate JWT claims according to options.
 */
function validateJwtClaims(payload: JwtPayload, options?: VerifyJwtOptions): void {
  if (!options) {
    return;
  }

  const now = options.currentDate
    ? Math.floor(options.currentDate.getTime() / 1000)
    : Math.floor(Date.now() / 1000);
  const tolerance = options.clockTolerance ? parseDuration(options.clockTolerance) : 0;

  // Validate required claims
  if (options.requiredClaims) {
    for (const claim of options.requiredClaims) {
      if (!(claim in payload)) {
        throw new Error(`Missing required claim: "${claim}"`);
      }
    }
  }

  // Validate audience
  if (options.audience !== undefined) {
    const expectedAudiences = Array.isArray(options.audience)
      ? options.audience
      : [options.audience];
    const actualAudiences = payload.aud
      ? Array.isArray(payload.aud)
        ? payload.aud
        : [payload.aud]
      : [];

    // Validate that all audience values are strings
    const validAudiences = actualAudiences.filter((aud) => typeof aud === 'string') as string[];
    const hasMatch = expectedAudiences.some((expected) => validAudiences.includes(expected));
    if (!hasMatch) {
      throw new Error(`Invalid JWT: unexpected "aud" claim value`);
    }
  }

  // Validate issuer
  if (options.issuer !== undefined) {
    const expectedIssuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
    if (typeof payload.iss !== 'string' || !expectedIssuers.includes(payload.iss)) {
      throw new Error(`Invalid JWT: unexpected "iss" claim value`);
    }
  }

  // Validate subject
  if (options.subject !== undefined) {
    if (typeof payload.sub !== 'string' || payload.sub !== options.subject) {
      throw new Error(`Invalid JWT: unexpected "sub" claim value`);
    }
  }

  // Validate expiration time
  if (payload.exp !== undefined) {
    if (typeof payload.exp !== 'number') {
      throw new Error('Invalid JWT: "exp" claim must be a number');
    }
    if (now - tolerance >= payload.exp) {
      throw new Error('Invalid JWT: token has expired');
    }
  }

  // Validate not before time
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number') {
      throw new Error('Invalid JWT: "nbf" claim must be a number');
    }
    if (now + tolerance < payload.nbf) {
      throw new Error('Invalid JWT: token is not yet valid');
    }
  }

  // Validate max token age
  if (options.maxTokenAge !== undefined && payload.iat !== undefined) {
    if (typeof payload.iat !== 'number') {
      throw new Error('Invalid JWT: "iat" claim must be a number');
    }
    const maxAge = parseDuration(options.maxTokenAge);
    const age = now - payload.iat;
    if (age > maxAge + tolerance) {
      throw new Error('Invalid JWT: token is too old');
    }
  }
}
