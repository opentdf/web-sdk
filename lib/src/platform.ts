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
import { AuthProvider } from '../tdf3/index.js';

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
  // Optional authentication provider for generating auth interceptor.
  authProvider?: AuthProvider;
  // Array of custom interceptors to apply to rpc requests.
  interceptors?: Interceptor[];
  // Base URL of the platform API.
  platformUrl: string;
}

/**
 * A client for interacting with the Platform using the Connect RPC framework.
 *
 * This client provides access to various services offered by the Platform, such as
 * authorization, entity resolution, key access, policy management, and more. It uses
 * the Connect RPC framework to communicate with the platform's API endpoints.
 *
 * This client supports authentication via an `AuthProvider` or custom interceptors, which can
 * be used to add authentication headers or other custom logic to outgoing requests.
 *
 */
export class PlatformClient {
  readonly v1: PlatformServices;

  constructor(options: PlatformClientOptions) {
    const interceptors: Interceptor[] = [];

    if (options.authProvider) {
      const authInterceptor = createAuthInterceptor(options.authProvider);
      interceptors.push(authInterceptor);
    }

    if (options.interceptors?.length) {
      interceptors.push(...options.interceptors);
    }

    const transport = createConnectTransport({
      baseUrl: options.platformUrl,
      interceptors,
    });

    this.v1 = {
      authorization: createClient(AuthorizationService, transport),
      entityResolution: createClient(EntityResolutionService, transport),
      access: createClient(AccessService, transport),
      action: createClient(ActionService, transport),
      attributes: createClient(AttributesService, transport),
      keyAccessServerRegistry: createClient(KeyAccessServerRegistryService, transport),
      namespace: createClient(NamespaceService, transport),
      resourceMapping: createClient(ResourceMappingService, transport),
      subjectMapping: createClient(SubjectMappingService, transport),
      unsafe: createClient(UnsafeService, transport),
      wellknown: createClient(WellKnownService, transport),
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
