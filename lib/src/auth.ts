export interface AuthProvider {
  /**
   * This function should be called if the consumer of this auth provider changes the client keypair,
   * or wishes to set the keypair after creating the object.
   *
   * Calling this function will (optionally) trigger a forcible token refresh using the cached refresh token,
   * and update the auth server config with the current key.
   *
   * @param clientPubkey - the client's public key, base64 encoded. Will be bound to the OIDC token.
   */
  updateClientPublicKey(clientPubkey: string): Promise<void>;

  /**
   * Compute an auth header value for an http request, to associate the session with the current entity
   */
  authorization(): Promise<string>;
}
