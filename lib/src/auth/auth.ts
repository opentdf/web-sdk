import { type JWTHeaderParameters, type JWTPayload, type KeyLike, SignJWT } from 'jose';

export type HttpMethod =
  | 'GET'
  | 'HEAD'
  | 'POST'
  | 'PUT'
  | 'DELETE'
  | 'CONNECT'
  | 'OPTIONS'
  | 'TRACE'
  | 'PATCH';

/**
 * Generic HTTP request interface used by AuthProvider implementers.
 */
export class HttpRequest {
  headers: Record<string, string>;

  method: HttpMethod;

  params?: object;

  url: string;

  body?: BodyInit | null;

  constructor() {
    this.headers = {};
    this.params = {};
    this.method = 'POST';
    this.url = '';
  }
}

/**
 * Appends the given `newHeaders` to the headers listed in HttpRequest, overwriting
 * any with the same name. NOTE: Case sensitive.
 * @param httpReq the source request
 * @param newHeaders header name/value pairs
 * @returns an updated variant of the request
 */
export function withHeaders(httpReq: HttpRequest, newHeaders: Record<string, string>): HttpRequest {
  const headers = {
    ...httpReq.headers,
    ...newHeaders,
  };
  return { ...httpReq, headers };
}

function getTimestampInSeconds() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Generate a JWT (or JWS-ed object)
 * @param toSign the data to sign. Interpreted as JWTPayload but AFAIK this isn't required
 * @param privateKey an RSA key
 * @returns the signed object, with a JWS header. This may be a JWT.
 */
export async function reqSignature(
  toSign: unknown,
  privateKey: KeyLike,
  jwtProtectedHeader: JWTHeaderParameters = { alg: 'RS256' }
) {
  const now = getTimestampInSeconds();
  const anHour = 3600;
  return new SignJWT(toSign as JWTPayload)
    .setProtectedHeader(jwtProtectedHeader)
    .setIssuedAt(now - anHour)
    .setExpirationTime(now + anHour)
    .sign(privateKey);
}

/**
 * A utility type for getting and updating a bearer token to associate with
 * HTTP requests to the backend services, notably rewrap and upsert endpoints.
 *
 * In the TDF protocol, this bearer token will be a wrapper around a signed
 * ephemeral key, to be included in
 * [the claims object](https://github.com/opentdf/spec/blob/main/schema/ClaimsObject.md).
 */
export type AuthProvider = {
  /**
   * This function should be called if the consumer of this auth provider
   * changes the client keypair, or wishes to set the keypair after creating
   * the object.
   *
   * Calling this function will (optionally) trigger a forcible token refresh
   * using the cached refresh token, and update the auth server config with the
   * current key.
   *
   * @param signingKey the client signing key pair. Will be bound
   * to the OIDC token and require a DPoP header, when set.
   */
  updateClientPublicKey(signingKey?: CryptoKeyPair): Promise<void>;

  /**
   * Augment the provided http request with custom auth info to be used by backend services.
   *
   * @param httpReq - Required. An http request pre-populated with the data public key.
   */
  withCreds(httpReq: HttpRequest): Promise<HttpRequest>;
};

export function isAuthProvider(a?: unknown): a is AuthProvider {
  if (!a || typeof a != 'object') {
    return false;
  }
  return 'withCreds' in a;
}
