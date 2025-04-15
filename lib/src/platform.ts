// export client service definitions
export * as authorization from './platform/authorization/authorization_pb.js';
export * as common from './platform/common/common_pb.js';
export * as entityResolution from './platform/entityresolution/entity_resolution_pb.js';
export * as kas from './platform/kas/kas_pb.js';
export * as policyActions from './platform/policy/actions/actions_pb.js';
export * as policyAttributes from './platform/policy/attributes/attributes_pb.js';
export * as policyKasRegistry from './platform/policy/kasregistry/key_access_server_registry_pb.js';
export * as policyNamespaces from './platform/policy/namespaces/namespaces_pb.js';
export * as policyObjects from './platform/policy/objects_pb.js';
export * as policyRegisteredResources from './platform/policy/registeredresources/registered_resources_pb.js';
export * as policyResourceMapping from './platform/policy/resourcemapping/resource_mapping_pb.js';
export * as policySelectors from './platform/policy/selectors_pb.js';
export * as policySubjectMapping from './platform/policy/subjectmapping/subject_mapping_pb.js';
export * as policyUnsafe from './platform/policy/unsafe/unsafe_pb.js';
export * as wellknown from './platform/wellknownconfiguration/wellknown_configuration_pb.js';

// export Connect RPC framework
export * as platformConnectWeb from '@connectrpc/connect-web';
export * as platformConnect from '@connectrpc/connect';

import { createConnectTransport } from '@connectrpc/connect-web';
import { AuthProvider } from 'tdf3/index.js';

import { Client, createClient, Interceptor } from '@connectrpc/connect';
import { WellKnownService } from './platform/wellknownconfiguration/wellknown_configuration_pb.js';
import { AuthorizationService } from './platform/authorization/authorization_pb.js';
import { EntityResolutionService } from './platform/entityresolution/entity_resolution_pb.js';
import { AccessService } from './platform/kas/kas_pb.js';
import { ActionService } from './platform/policy/actions/actions_pb.js';
import { AttributesService } from './platform/policy/attributes/attributes_pb.js';
import { KeyAccessServerRegistryService } from './platform/policy/kasregistry/key_access_server_registry_pb.js';
import { NamespaceService } from './platform/policy/namespaces/namespaces_pb.js';
import { ResourceMappingService } from './platform/policy/resourcemapping/resource_mapping_pb.js';
import { SubjectMappingService } from './platform/policy/subjectmapping/subject_mapping_pb.js';
import { UnsafeService } from './platform/policy/unsafe/unsafe_pb.js';

export interface PlatformServices {
  authorization: Client<typeof AuthorizationService>;
  entityResolution: Client<typeof EntityResolutionService>;
  access: Client<typeof AccessService>;
  action: Client<typeof ActionService>;
  attributes: Client<typeof AttributesService>;
  keyAccessServerRegistry: Client<typeof KeyAccessServerRegistryService>;
  namespace: Client<typeof NamespaceService>;
  resourceMapping: Client<typeof ResourceMappingService>;
  subjectMapping: Client<typeof SubjectMappingService>;
  unsafe: Client<typeof UnsafeService>;
  wellknown: Client<typeof WellKnownService>;
}

export interface PlatformClientOptions {
  // Optional authentication provider for generating credentials.
  authProvider?: AuthProvider;

  // Whether to use the auth provider interceptor (default: true).
  useAuthProviderInterceptor?: boolean;

  // Array of custom interceptors to apply to rpc requests.
  clientInterceptors?: Interceptor[];

  // Base URL of the platform API.
  platformUrl: string;
}

export class PlatformClient {
  private readonly transport: ReturnType<typeof createConnectTransport>;
  readonly services: PlatformServices;

  constructor(options: PlatformClientOptions) {
    const useAuthProviderInterceptor = options.useAuthProviderInterceptor ?? true;

    if (!options.authProvider && !options.clientInterceptors?.length) {
      // TODO: define if this should throw
      console.warn('authProvider or clientInterceptors is required');
    }

    const interceptors: Interceptor[] = [];

    if (options.authProvider && useAuthProviderInterceptor) {
      const authInterceptor = createAuthInterceptor(options.authProvider);
      interceptors.push(authInterceptor);
    }

    if (options.clientInterceptors?.length) {
      interceptors.push(...options.clientInterceptors);
    }

    this.transport = createConnectTransport({
      baseUrl: options.platformUrl,
      interceptors,
    });

    this.services = {
      authorization: createClient(AuthorizationService, this.transport),
      entityResolution: createClient(EntityResolutionService, this.transport),
      access: createClient(AccessService, this.transport),
      action: createClient(ActionService, this.transport),
      attributes: createClient(AttributesService, this.transport),
      keyAccessServerRegistry: createClient(KeyAccessServerRegistryService, this.transport),
      namespace: createClient(NamespaceService, this.transport),
      resourceMapping: createClient(ResourceMappingService, this.transport),
      subjectMapping: createClient(SubjectMappingService, this.transport),
      unsafe: createClient(UnsafeService, this.transport),
      wellknown: createClient(WellKnownService, this.transport),
    };
  }
}

/**
 * Creates an interceptor that adds authentication headers to outgoing requests.
 *
 * This function uses the provided `AuthProvider` to generate authentication credentials
 * for each request. The `AuthProvider` is expected to implement a `withCreds` method
 * that returns an object containing authentication headers. These headers are then
 * added to the request before it is sent to the server.
 *
 * @param authProvider - An instance of `AuthProvider` used to generate authentication credentials.
 * @returns An `Interceptor` function that modifies requests to include authentication headers.
 */
function createAuthInterceptor(authProvider: AuthProvider): Interceptor {
  const authInterceptor: Interceptor = (next) => async (req) => {
    const token = await authProvider.withCreds({
      url: req.url,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    Object.entries(token.headers).forEach(([key, value]) => {
      req.header.set(key, value);
    });

    return await next(req);
  };
  return authInterceptor;
}
