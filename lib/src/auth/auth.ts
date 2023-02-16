import { type JWTHeaderParameters, type JWTPayload, type KeyLike, SignJWT } from 'jose';

export type Method =
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

  method: Method;

  params?: object;

  url: string;

  body?: BodyInit | null | unknown;

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
export abstract class AuthProvider {
  /**
   * This function should be called if the consumer of this auth provider
   * changes the client keypair, or wishes to set the keypair after creating
   * the object.
   *
   * Calling this function will (optionally) trigger a forcible token refresh
   * using the cached refresh token, and update the auth server config with the
   * current key.
   *
   * @param clientPubkey the client's public key, base64 encoded
   * @param signingKey the client signing key pair. Will be bound
   * to the OIDC token and require a DPoP header, when set.
   */
  abstract updateClientPublicKey(clientPubkey: string, signingKey?: CryptoKeyPair): Promise<void>;

  /**
   * Augment the provided http request with custom auth info to be used by backend services.
   *
   * @param httpReq - Required. An http request pre-populated with the data public key.
   */
  abstract withCreds(httpReq: HttpRequest): Promise<HttpRequest>;
}

/**
 * An AuthProvider encapsulates all logic necessary to authenticate to a backend service, in the
 * vein of <a href="https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/Credentials.html">AWS.Credentials</a>.
 * <br/><br/>
 * The client will call into its configured AuthProvider to decorate remote TDF service calls with necessary
 * authentication info. This approach allows the client to be agnostic to the auth scheme, allowing for
 * methods like identify federation and custom service credentials to be used and changed at the developer's will.
 * <br/><br/>
 * This class is not intended to be used on its own. See the documented subclasses for public-facing implementations.
 * <ul>
 * <li><a href="EmailCodeAuthProvider.html">EmailCodeAuthProvider</li>
 * <li><a href="GoogleAuthProvider.html">GoogleAuthProvider</li>
 * <li><a href="O365AuthProvider.html">O365AuthProvider</li>
 * <li><a href="OutlookAuthProvider.html">OutlookAuthProvider</li>
 * <li><a href="VirtruCredentialsAuthProvider.html">VirtruCredentialsAuthProvider</li>
 * </ul>
 */
export abstract class AppIdAuthProvider {
  /**
   * Augment the provided http request with custom auth info to be used by backend services.
   *
   * @param httpReq - Required. An http request pre-populated with the data public key.
   */
  abstract withCreds(httpReq: HttpRequest): Promise<HttpRequest>;

  abstract _getName(): string;
}

export default AppIdAuthProvider;
