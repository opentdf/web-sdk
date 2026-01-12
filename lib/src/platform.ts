// export Connect RPC framework
export * as platformConnectWeb from '@connectrpc/connect-web';
export * as platformConnect from '@connectrpc/connect';

import { createConnectTransport } from '@connectrpc/connect-web';
import { AuthProvider } from '../tdf3/index.js';

import { Client, createClient, Interceptor } from '@connectrpc/connect';
import { WellKnownService } from './platform/wellknownconfiguration/wellknown_configuration_pb.js';
import { AuthorizationService } from './platform/authorization/authorization_pb.js';
import { AuthorizationService as AuthorizationServiceV2 } from './platform/authorization/v2/authorization_pb.js';
import { EntityResolutionService } from './platform/entityresolution/entity_resolution_pb.js';
import { AccessService } from './platform/kas/kas_pb.js';
import { ActionService } from './platform/policy/actions/actions_pb.js';
import { AttributesService } from './platform/policy/attributes/attributes_pb.js';
import { KeyAccessServerRegistryService } from './platform/policy/kasregistry/key_access_server_registry_pb.js';
import { KeyManagementService } from './platform/policy/keymanagement/key_management_pb.js';
import { Service as ObligationService } from './platform/policy/obligations/obligations_pb.js';
import { NamespaceService } from './platform/policy/namespaces/namespaces_pb.js';
import { RegisteredResourcesService } from './platform/policy/registeredresources/registered_resources_pb.js';
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
  keyManagement: Client<typeof KeyManagementService>;
  namespace: Client<typeof NamespaceService>;
  obligation: Client<typeof ObligationService>;
  registeredResources: Client<typeof RegisteredResourcesService>;
  resourceMapping: Client<typeof ResourceMappingService>;
  subjectMapping: Client<typeof SubjectMappingService>;
  unsafe: Client<typeof UnsafeService>;
  wellknown: Client<typeof WellKnownService>;
}

export interface PlatformServicesV2 {
  authorization: Client<typeof AuthorizationServiceV2>;
}

export interface PlatformClientOptions {
  /** Optional authentication provider for generating auth interceptor. */
  authProvider?: AuthProvider;
  /** Array of custom interceptors to apply to rpc requests. */
  interceptors?: Interceptor[];
  /** Base URL of the platform API. */
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
 * @example
 * ```
 * import { AuthProviders, OpenTDF } from '@opentdf/sdk';
 * import { PlatformClient } from '@opentdf/sdk/platform';
 *
 * const authProvider: AuthProvider = await AuthProviders.refreshAuthProvider({...});
 * const platform = new PlatformClient({
 *   authProvider,
 *   platformUrl: 'https://platform.example.com',
 * });
 *
 * const wellKnownResponse = await platform.v1.wellknown.getWellKnownConfiguration({});
 * console.log('Well-known configuration:', wellKnownResponse.configuration);
 * ```
 */

export class PlatformClient {
  readonly v1: PlatformServices;
  readonly v2: PlatformServicesV2;

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
      keyManagement: createClient(KeyManagementService, transport),
      namespace: createClient(NamespaceService, transport),
      obligation: createClient(ObligationService, transport),
      registeredResources: createClient(RegisteredResourcesService, transport),
      resourceMapping: createClient(ResourceMappingService, transport),
      subjectMapping: createClient(SubjectMappingService, transport),
      unsafe: createClient(UnsafeService, transport),
      wellknown: createClient(WellKnownService, transport),
    };

    this.v2 = {
      authorization: createClient(AuthorizationServiceV2, transport),
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
 */
function createAuthInterceptor(authProvider: AuthProvider): Interceptor {
  const authInterceptor: Interceptor = (next) => async (req) => {
    const url = new URL(req.url);
    const pathOnly = url.pathname;
    // Signs only the path of the url in the request
    const token = await authProvider.withCreds({
      url: pathOnly,
      method: 'POST',
      // Start with any headers Connect already has
      headers: {
        ...Object.fromEntries(req.header.entries()),
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
