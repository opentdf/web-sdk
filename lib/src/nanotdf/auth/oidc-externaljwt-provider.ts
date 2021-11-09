import VirtruOIDC from './virtru-oidc.js';
import { IOIDCExternalJwtProvider } from '../interfaces/OIDCInterface.js';
import { AuthProvider } from 'auth.js';

/**
 * OIDC External JWT Provider for browser contexts.
 *
 * Both browser and non-browser flows use OIDC, but the supported OIDC auth mechanisms differ between
 * public (e.g. browser) clients, and confidential (e.g. Node) clients.
 *
 * This provider supports External JWT token exchange auth. This flow assumes that the client has previously authenticated
 * with an external 3rd-party IdP that oidcOrigin has been configured to trust.
 *
 * The client can supply this provider with a JWT issued by that trusted 3rd-party IdP, and that JWT will be exchanged
 * for a tokenset with TDF claims.
 *
 * The client's public key must be set in all OIDC token requests in order to recieve a token with valid
 * Virtru claims. The public key may be passed to this provider's constructor, or supplied post-construction by calling
 * @see updateClientPublicKey
 * which will force an explicit token refresh
 *
 * Does not inherit from the "base class provider" like other providers because a circular dep
 * isn't worth abstracting a 2-line function in a language with no typechecking, come on people.
 */

export class OIDCExternalJwtProvider implements AuthProvider {
  oidcAuth: VirtruOIDC;
  externalJwt?: string;

  /**
   * @param {string} organizationName - the organization the calling user belongs to (in Keycloak, this is the Realm). Required.
   * @param {string} [clientPubKey] - the client's public key, base64 encoded. Will be bound to the OIDC token. Optional. If not set in the constructor,
   * MUST be set via @see updateClientPublicKey after the fact, before calling other functions.
   * @param {string} clientId - The OIDC client ID used for token issuance and exchange flows.
   * @param {string} externalJwt- A valid OIDC token from a 3rd-party IdP Virtru has a trust relation ship with.
   * @param {string} oidcOrigin - The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth'
   */
  constructor({
    organizationName,
    clientPubKey,
    clientId,
    externalJwt,
    oidcOrigin,
  }: IOIDCExternalJwtProvider) {
    if (!organizationName || !clientId || !externalJwt) {
      throw new Error(
        'To use this browser-only provider you must supply organizationName/clientId/JWT from trusted external IdP'
      );
    }

    this.oidcAuth = new VirtruOIDC({
      organizationName,
      clientPubKey,
      clientId,
      oidcOrigin,
    });

    this.externalJwt = externalJwt;
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
  async updateClientPublicKey(clientPubKey: string): Promise<void> {
    this.oidcAuth.refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubKey);
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
  async authorization(): Promise<string> {
    //If we've been seeded with an externally-issued JWT, consume it
    //and exchange it for a Virtru bearer token.
    if (this.externalJwt) {
      this.oidcAuth.exchangeExternalJwt(this.externalJwt);
      delete this.externalJwt;
    }
    const accessToken = this.oidcAuth.getCurrentAccessToken();

    // NOTE It is generally best practice to keep headers under 8KB
    return `Bearer ${accessToken}`;
  }
}
