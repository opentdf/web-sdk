import { JWTPayload, SignJWT } from "jose";

export type Method =
  | 'get'
  | 'head'
  | 'post'
  | 'put'
  | 'delete'
  | 'connect'
  | 'options'
  | 'trace'
  | 'patch';

/**
 * Generic HTTP request interface used by AuthProvider implementers.
 */
export type HttpRequest = {
  headers: Record<string, string>;

  method: Method;

  /** The resource to query */
  url: string;

  body?: BodyInit | null | unknown;
};

export function withHeaders(httpReq: HttpRequest, newHeaders: Record<string, string>): HttpRequest {
  const headers = {
    ...httpReq.headers,
    ...newHeaders,
  };
  return { ...httpReq, headers };
}

export async function reqSignature(toSign: unknown, key: CryptoKeyPair) {
  return new SignJWT(toSign as JWTPayload)
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(key.privateKey);
}

/**
 * A utility type for getting and updating a bearer token to associate with
 * HTTP requests to the backend services, notably rewrap and upsert endpoints.
 *
 * In the TDF protocol, this bearer token will be a wrapper around a signed
 * ephemeral key, to be included in
 * [the claims object](https://github.com/opentdf/spec/blob/main/schema/ClaimsObject.md).
 */
export interface AuthProvider {
  /**
   * This function should be called if the consumer of this auth provider
   * changes the client keypair, or wishes to set the keypair after creating
   * the object.
   *
   * Calling this function will (optionally) trigger a forcible token refresh
   * using the cached refresh token, and update the auth server config with the
   * current key.
   *
   * @param signingKey the client's public key, base64 encoded. Will be bound to the OIDC token.
   */
  updateClientPublicKey(signingKey: CryptoKeyPair): Promise<void>;

  /**
   * Augment the provided http request with custom auth info to be used by backend services.
   *
   * @param httpReq - Required. An http request pre-populated with the data public key.
   */
  injectAuth(httpReq: HttpRequest): Promise<HttpRequest>;
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
export interface AppIdAuthProvider {
  /**
   * Augment the provided http request with custom auth info to be used by backend services.
   *
   * @param httpReq - Required. An http request pre-populated with the data public key.
   */
  injectAuth(httpReq: HttpRequest): Promise<HttpRequest>;

  _getName(): string;
}
