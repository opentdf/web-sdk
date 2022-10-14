import {
  ClientSecretCredentials,
  ExternalJwtCredentials,
  OIDCCredentials,
  RefreshTokenCredentials,
} from './OIDCCredentials.js';
import { OIDCClientCredentialsProvider } from './oidc-clientcredentials-provider.js';
import { OIDCExternalJwtProvider } from './oidc-externaljwt-provider.js';
import { AuthProvider } from './auth.js';
import { OIDCRefreshTokenProvider } from './oidc-refreshtoken-provider.js';
import { isBrowser } from '../utils.js';

/**
 * Creates an OIDC Client Credentials Provider for non-browser contexts.
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
 * {@link updateClientPublicKey} which will force an explicit token refresh
 *
 */
export const clientSecretAuthProvider = async (
  clientConfig: ClientSecretCredentials,
  clientPubKey?: string
): Promise<AuthProvider> => {
  return new OIDCClientCredentialsProvider({
    clientPubKey: clientPubKey,
    clientId: clientConfig.clientId,
    clientSecret: clientConfig.clientSecret,
    oidcOrigin: clientConfig.oidcOrigin,
  });
};

/**
 * Create an OIDC External JWT Provider for browser contexts.
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
 * {@link updateClientPublicKey}, which will force an explicit token refresh.
 */
export const externalAuthProvider = async (
  clientConfig: ExternalJwtCredentials,
  clientPubKey?: string
): Promise<AuthProvider> => {
  return new OIDCExternalJwtProvider({
    clientPubKey: clientPubKey,
    clientId: clientConfig.clientId,
    externalJwt: clientConfig.externalJwt,
    oidcOrigin: clientConfig.oidcOrigin,
  });
};

/**
 * Creates an OIDC Refresh Token Provider for browser and non-browser contexts.
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
 * {@link updateClientPublicKey} which will force an explicit token refresh
 */
export const refreshAuthProvider = async (
  clientConfig: RefreshTokenCredentials,
  clientPubKey?: string
): Promise<AuthProvider> => {
  return new OIDCRefreshTokenProvider({
    clientPubKey: clientPubKey,
    clientId: clientConfig.clientId,
    externalRefreshToken: clientConfig.oidcRefreshToken,
    oidcOrigin: clientConfig.oidcOrigin,
  });
};

/**
 * Generate an auth provder.
 * @param clientConfig OIDC client credentials
 * @param clientPubKey Client identification
 * @returns a promise for a new auth provider with the requested excahnge type
 */
export const clientAuthProvider = async (
  clientConfig: OIDCCredentials,
  clientPubKey?: string
): Promise<AuthProvider> => {
  if (!clientConfig.clientId) {
    throw new Error('Client ID must be provided to constructor');
  }

  if (isBrowser()) {
    //If you're in a browser and passing client secrets, you're Doing It Wrong.
    // if (clientConfig.clientSecret) {
    //   throw new Error('Client credentials not supported in a browser context');
    // }
    //Are we exchanging a refreshToken for a bearer token (normal AuthCode browser auth flow)?
    //If this is a browser context, we expect the caller to handle the initial
    //browser-based OIDC login and authentication process against the OIDC endpoint using their chosen method,
    //and provide us with a valid refresh token/clientId obtained from that process.
    switch (clientConfig.exchange) {
      case 'refresh': {
        return refreshAuthProvider(clientConfig, clientPubKey);
      }
      case 'external': {
        return externalAuthProvider(clientConfig, clientPubKey);
      }
      case 'client': {
        return clientSecretAuthProvider(clientConfig, clientPubKey);
      }
      default:
        throw new Error(`Unsupported client type`);
    }
  }
  //If you're NOT in a browser and are NOT passing client secrets, you're Doing It Wrong.
  //If this is not a browser context, we expect the caller to supply their client ID and client secret, so that
  // we can authenticate them directly with the OIDC endpoint.
  if (clientConfig.exchange !== 'client') {
    throw new Error(
      'If using client credentials, must supply both client ID and client secret to constructor'
    );
  }
  return clientSecretAuthProvider(clientConfig, clientPubKey);
};

export * from './auth.js';
export * from './OIDCCredentials.js';
