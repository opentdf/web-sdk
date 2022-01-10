// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { AccessToken, AccessTokenConfig } from '../../keycloak/AccessToken.js';
import { IVirtruOIDC } from '../interfaces/OIDCInterface.js';

/**
 * Class that provides OIDC functionality to auth providers.
 *
 * Note that this class itself is not a provider - providers implement `../auth.js#AuthProvider`
 * and make use of this class.
 *
 * Both browser and non-browser flows use OIDC, but the supported OIDC auth mechanisms differ between
 * public (e.g. browser) clients, and confidential (e.g. Node) clients.
 *
 * The non-browser flow just expects a clientId and clientSecret to be provided in the clientConfig, and will use that
 * to grant tokens via the OIDC clientCredentials flow.
 *
 * For either kind of client, the client's public key must be set in all OIDC token requests in order to recieve a token
 * with valid TDF claims. The public key may be passed to this provider's constructor, or supplied post-construction by
 * calling @see updateClientPublicKey which will force an explicit token refresh
 *
 */
export default class VirtruOIDC {
  protected authMode: 'browser' | 'credentials';
  protected clientPubKey?: string;
  protected accessTokenGetter: AccessToken;
  protected currentAccessToken?: string;

  /**
   * If clientId and clientSecret are provided, clientCredentials mode will be assumed.
   *
   * If clientId and clientSecret are not provided, browser mode will be assumed, and @see refreshTokenWithVirtruClaims must be
   * manually called during object initialization to do a token exchange.
   * @param {string} organizationName - the organization the calling user belongs to (in Keycloak, this is the Realm). Required.
   * @param {string} [clientPubKey] - the client's public key, base64 encoded. Will be bound to the OIDC token. Optional. If not set in the constructor,
   * MUST be set via @see updateClientPublicKey after the fact, before calling other functions.
   * @param {string} clientId - If using client credentials mode, the client ID. Optional, used for non-browser contexts.
   * @param {string} [clientSecret] - If using client credentials mode, the client secret. Optional, used for non-browser contexts.
   * @param {string} oidcOrigin - The endpoint of the OIDC IdP to authenticate against, ex. 'https://virtru.com/auth'
   */
  constructor({ organizationName, clientPubKey, clientId, clientSecret, oidcOrigin }: IVirtruOIDC) {
    if (!organizationName || !clientId) {
      throw new Error(
        'To use any OIDC auth mode you must supply your organizationName and clientId, at a minimum'
      );
    }
    let keycloakConfig: AccessTokenConfig = {
      realm: organizationName,
      client_id: clientId,
      auth_server_url: oidcOrigin,
      // pubkey may be `null` at this point, that's fine - it can be set later by the caller
      // via `refreshTokenClaimsWithClientPubkey()` - it just has to be in place before we try to get a token from Keycloak.
      virtru_client_pubkey: clientPubKey,
    };

    //If we have a client secret, we must be using client credentials, and this is not
    // a public client (aka this is not a browser context)
    if (clientSecret) {
      keycloakConfig = {
        client_secret: clientSecret,
        auth_mode: 'credentials',
        ...keycloakConfig,
      };
    } else {
      //This is a browser client which is exchanging a Keycloak IdP-issued refresh token
      keycloakConfig = {
        auth_mode: 'browser',
        ...keycloakConfig,
      };
    }
    this.authMode = keycloakConfig.auth_mode || 'browser';
    this.clientPubKey = clientPubKey;
    this.accessTokenGetter = new AccessToken(keycloakConfig);
  }

  /**
   * This function should be called if the consumer of this auth provider changes the client keypair,
   * or wishes to set the keypair after creating the object.
   *
   * Calling this function will trigger a forcible token refresh using the cached refresh token, and contact the auth server.
   *
   * @param {string} clientPubKey - the client's public key, base64 encoded. Will be bound to the OIDC token. Optional. If not set in the constructor,
   */
  async refreshTokenClaimsWithClientPubkeyIfNeeded(clientPubKey: string): Promise<void> {
    // If we already have a token, and the pubkey changes,
    // we need to force a refresh now - otherwise
    // we can wait until we create the token for the first time
    if (this.currentAccessToken && clientPubKey === this.accessTokenGetter.virtru_client_pubkey) {
      return;
    }
    this.accessTokenGetter.virtru_client_pubkey = clientPubKey;
    this.clientPubKey = clientPubKey;
  }

  async getCurrentAccessToken(): Promise<string> {
    if (!this.clientPubKey) {
      throw new Error(
        'Client public key was not set via `updateClientPublicKey` or passed in via constructor, cannot fetch OIDC token with valid Virtru claims'
      );
    }
    if (!this.currentAccessToken) {
      this.currentAccessToken = await this.accessTokenGetter.get();
    }
    return this.currentAccessToken;
  }

  /**
   * This function checks to see if we need to perform the one-time operation of exchanging a valid OIDC token
   * that lacks Virtru claims (because it hasn't been associated with a client pubkey yet) for
   *
   */
  async exchangeExternalRefreshToken(externalRefreshToken: string): Promise<string> {
    if (!externalRefreshToken) {
      throw new Error('No external refresh token provided!');
    }

    //Do a token exchange now, taking the provided refresh token and requesting a new access token
    // from Keycloak with updated Virtru claims
    this.currentAccessToken = await this.accessTokenGetter.refresh(externalRefreshToken);
    return this.currentAccessToken;
  }

  /**
   * This function checks to see if we need to perform the one-time operation of exchanging a valid OIDC token
   * that lacks Virtru claims (because it hasn't been associated with a client pubkey yet) for
   *
   */
  async exchangeExternalJwt(externalJwt: string): Promise<string> {
    if (!externalJwt) {
      throw new Error('No external JWT provided!');
    }

    //Do a token exchange taking the provided exernal 3rd-party token and requesting a new access token
    // from Keycloak with updated Virtru claims
    const cat = await this.accessTokenGetter.exchangeJwt(externalJwt);
    this.currentAccessToken = cat;
    return cat;
  }
}
