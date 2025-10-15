import { NetworkError } from '../errors.js';
import { AuthProvider } from '../auth/auth.js';
import { extractRpcErrorMessage, getPlatformUrlFromKasEndpoint } from '../utils.js';
import { PlatformClient } from '../platform.js';
import { Value } from './attributes.js';
import { GetAttributeValuesByFqnsResponse } from '../platform/policy/attributes/attributes_pb.js';
import { GetNamespaceResponse } from '../platform/policy/namespaces/namespaces_pb.js';
import { Certificate } from '../platform/policy/objects_pb.js';

// TODO KAS: go over web-sdk and remove policyEndpoint that is only defined to be used here
export async function attributeFQNsAsValues(
  platformUrl: string,
  authProvider: AuthProvider,
  ...fqns: string[]
): Promise<Value[]> {
  platformUrl = getPlatformUrlFromKasEndpoint(platformUrl);
  const platform = new PlatformClient({ authProvider, platformUrl });

  let response: GetAttributeValuesByFqnsResponse;
  try {
    response = await platform.v1.attributes.getAttributeValuesByFqns({
      fqns,
    });
  } catch (e) {
    throw new NetworkError(
      `[${platformUrl}] [GetAttributeValuesByFqns] ${extractRpcErrorMessage(e)}`
    );
  }

  const values: Value[] = [];
  for (const [fqn, av] of Object.entries(response.fqnAttributeValues)) {
    const value = av.value;
    if (!value) {
      console.log(`Missing value definition for [${fqn}]; is this a valid attribute?`);
      continue;
    }
    if (value && av.attribute && !value?.attribute) {
      value.attribute = av.attribute;
    }

    values.push(value);
  }
  return values;
}

// Get root certificates from a namespace
export async function getRootCertsFromNamespace(
  platformUrl: string,
  authProvider?: AuthProvider,
  namespaceId?: string,
  fqn?: string
): Promise<Certificate[]> {
  platformUrl = getPlatformUrlFromKasEndpoint(platformUrl);
  const platform = new PlatformClient({ authProvider, platformUrl });

  let response: GetNamespaceResponse;
  try {
    response = await platform.v1.namespace.getNamespace({
      id: '', // deprecated field, but required
      identifier: namespaceId
        ? { case: 'namespaceId', value: namespaceId }
        : fqn
          ? { case: 'fqn', value: fqn }
          : { case: undefined, value: undefined },
    });
  } catch (e) {
    throw new NetworkError(`[${platformUrl}] [GetNamespace] ${extractRpcErrorMessage(e)}`);
  }

  if (!response.namespace) {
    throw new NetworkError(`[${platformUrl}] [GetNamespace] Namespace not found`);
  }

  return response.namespace.rootCerts || [];
}
