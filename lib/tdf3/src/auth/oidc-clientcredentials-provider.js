import VirtruOIDC from './virtru-oidc';

/**
 * OIDC Client Credentials Provider for non-browser contexts.
 *
 * Both browser and non-browser flows use OIDC, but the supported OIDC auth mechanisms differ between
 * public (e.g. browser) clients, and confidential (e.g. Node) clients.
 *
 * This provider supports Client Credentials auth, where the client has previously been issued a ClientID and ClientSecret.
 * Browser contexts should *never* use Client Credentials auth, as ClientSecrets are not secure for public client flows,
 * and should use one of the other Authorization Code-based OIDC auth mechanisms instead.
 *
 * This just expects a clientId and clientSecret to be provided in the clientConfig, and will use that
 * to grant tokens via the OIDC clientCredentials flow.
 *
 * The client's public key must be set in all OIDC token requests in order to recieve a token with valid
 * Virtru claims. The public key may be passed to this provider's constructor, or supplied post-construction by calling
 * @see setClientPubkey
 * which will force an explicit token refresh
 *
 */
class OIDCClientCredentialsProvider {
  /**
   *
   * @param {string} organizationName - the organization the calling user belongs to (in Keycloak, this is the Realm).
   * @param {string} [clientPubKey] - the client's public key, base64 encoded. Will be bound to the OIDC token. Optional. If not set in the constructor,
   * MUST be set via @see setClientPubkey after the fact, before calling other functions.
   * @param {string} clientId - The OIDC client ID used for token issuance and exchange flows.
   * @param {string} clientSecret - The OIDC client secret, used for token issuance and exchange flows.
   * @param {string} oidcOrigin - The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth'
   */
  constructor({
    organizationName,
    clientPubKey = null,
    clientId = null,
    clientSecret = null,
    oidcOrigin = null,
  }) {
    if (!organizationName || !clientId || !clientSecret) {
      throw new Error(
        'To use this nonbrowser-only provider you must supply organizationName/clientId/clientSecret'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      organizationName,
      clientPubKey,
      clientId,
      clientSecret,
      oidcOrigin,
    });
  }

  /**
   * This function should be called if the consumer of this auth provider changes the client keypair,
   * or wishes to set the keypair after creating the object.
   *
   * Calling this function will (optionally) trigger a forcible token refresh using the cached refresh token,
   * and update the auth server config with the current key.
   *
   * @param {string} clientPubkey - the client's public key, base64 encoded. Will be bound to the OIDC token.
   */
  async setClientPubkey(clientPubkey) {
    await this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubkey);
  }

  /**
   * Augment the provided http request with custom auth info to be used by downstream services (KAS, etc).
   *
   * @param httpReq - Required. The KAS (or other Virtru downstream service) request to decorate with auth.
   *
   * @throws AuthException if the function is not able to generate auth credentials. Non-recoverable.
   * @throws TransientAuthProviderException if the function is not able to generate auth credentials due to a transient issue. Recoverable.
   * @throws IOException if reading from the disk or network failed. Recoverable.
   * @returns Nothing.
   */
  async injectAuth(httpReq) {
    let accessToken = await this.oidcAuth.getCurrentAccessToken();

    // NOTE It is generally best practice to keep headers under 8KB
    httpReq.headers.Authorization = `Bearer ${accessToken}`;
  }
}

export default OIDCClientCredentialsProvider;
