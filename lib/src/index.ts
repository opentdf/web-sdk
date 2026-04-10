export { type AuthProvider, type HttpMethod, HttpRequest, withHeaders } from './auth/auth.js';
export * as AuthProviders from './auth/providers.js';
export {
  authTokenInterceptor,
  authTokenDPoPInterceptor,
  authProviderInterceptor,
  type AuthConfig,
  type DPoPInterceptor,
  type DPoPInterceptorOptions,
  type Interceptor,
  type TokenProvider,
} from './auth/interceptors.js';
export {
  clientCredentialsTokenProvider,
  refreshTokenProvider,
  externalJwtTokenProvider,
  type ClientCredentialsTokenProviderOptions,
  type RefreshTokenProviderOptions,
  type ExternalJwtTokenProviderOptions,
} from './auth/token-providers.js';
export { attributeFQNsAsValues } from './policy/api.js';
export * as EntityIdentifiers from './platform/authorization/entity-identifiers.js';
export {
  listAttributes,
  validateAttributes,
  attributeExists,
  attributeValueExists,
} from './policy/discovery.js';
export { version, clientType, tdfSpecVersion } from './version.js';
export { PlatformClient, type PlatformClientOptions, type PlatformServices } from './platform.js';
export * from './opentdf.js';
export {
  TdfError,
  PermissionDeniedError,
  IntegrityError,
  InvalidFileError,
  DecryptError,
  NetworkError,
  AttributeValidationError,
  AttributeNotFoundError,
  ConfigurationError,
} from './errors.js';
export * from './seekable.js';
export * from '../tdf3/src/models/index.js';
