import VirtruOIDC from './virtru-oidc';

/**
 * OIDC Refresh Token Provider for browser and non-browser contexts.
 *
 * Both browser and non-browser flows use OIDC, but the supported OIDC auth mechanisms differ between
 * public (e.g. browser) clients, and confidential (e.g. Node) clients.
 *
 * This provider supports Refresh Token auth. This flow assumes the client has already authenticated with the OIDC
 * IdP using the OIDC flow fo their choice, and can provide a Refresh Token which will be exchanged (along with the client pubkey)
 * for a new tokenset containing valid TDF claims.
 *
 * The client's public key must be set in all OIDC token requests in order to recieve a token with valid
 * Virtru claims. The public key may be passed to this provider's constructor, or supplied post-construction by calling
 * @see setClientPubkey
 * which will force an explicit token refresh
 *
 * Does not inherit from the "base class provider" like other providers because a circular dep
 * isn't worth abstracting a 2-line function in a language with no typechecking, come on people.
 */
class OIDCRefreshTokenProvider {
  /**
   * @param {string} organizationName - the organization the calling user belongs to (in Keycloak, this is the Realm).
   * @param {string} [clientPubKey] - the client's public key, base64 encoded. Will be bound to the OIDC token. Optional. If not set in the constructor,
   * MUST be set via @see setClientPubkey after the fact, before calling other functions.
   * @param {string} clientId - The OIDC client ID used for token issuance and exchange flows.
   * @param {string} [clientSecret] - If using in a non-browser context, the client secret. Optional, used only for non-browser contexts.
   * @param {string} oidcRefreshToken - A valid OIDC refresh token, which will be consumed and exchanged for a valid OIDC tokenset with TDF claims
   * @param {string} oidcOrigin - The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth'
   */
  constructor({
    organizationName,
    clientPubKey = null,
    clientId = null,
    clientSecret = null,
    externalRefreshToken = null,
    oidcOrigin = null,
  }) {
    if (!organizationName || !clientId || !externalRefreshToken) {
      throw new Error(
        'To use this browser-only provider you must supply organizationName/clientId/valid OIDC refresh token'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      organizationName,
      clientPubKey,
      clientId,
      clientSecret,
      oidcOrigin,
    });
    this.clientPubKey = clientPubKey;
    this.externalRefreshToken = externalRefreshToken;
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
    //If we've been seeded with an externally-issued refresh token, consume it
    //and exchange it for a Virtru bearer token - if it's already been consumed,
    //skip this step
    if (this.externalRefreshToken) {
      await this.oidcAuth.exchangeExternalRefreshToken(this.externalRefreshToken);
      this.externalRefreshToken = null;
    }

    let accessToken = await this.oidcAuth.getCurrentAccessToken();

    // NOTE It is generally best practice to keep headers under 8KB
    httpReq.headers.Authorization = `Bearer ${accessToken}`;
  }
}

export default OIDCRefreshTokenProvider;
