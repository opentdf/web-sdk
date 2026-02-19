export { type AuthProvider, type HttpMethod, HttpRequest, withHeaders } from './auth/auth.js';
export * as AuthProviders from './auth/providers.js';
export { attributeFQNsAsValues } from './policy/api.js';
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
