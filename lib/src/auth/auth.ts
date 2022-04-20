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
   * @param clientPubkey the client's public key, base64 encoded. Will be bound to the OIDC token.
   */
  updateClientPublicKey(clientPubkey: string): Promise<void>;

  /**
   * Compute an auth header value for an http request, to associate the session with the current entity
   */
  authorization(): Promise<string>;
}
