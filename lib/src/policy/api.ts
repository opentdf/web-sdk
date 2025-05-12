import { NetworkError } from '../errors.js';
import { AuthProvider } from '../auth/auth.js';
import { extractRpcErrorMessage, rstrip } from '../utils.js';
import { PlatformClient } from '../platform.js';
import { Value } from './attributes.js';
import { GetAttributeValuesByFqnsResponse } from '../platform/policy/attributes/attributes_pb.js';

// TODO KAS: go over web-sdk and remove policyEndpoint that is only defined to be used here
export async function attributeFQNsAsValues(
  platformUrl: string,
  authProvider: AuthProvider,
  ...fqns: string[]
): Promise<Value[]> {
  const avs = new URLSearchParams();
  for (const fqn of fqns) {
    avs.append('fqns', fqn);
  }
  avs.append('withValue.withKeyAccessGrants', 'true');
  avs.append('withValue.withAttribute.withKeyAccessGrants', 'true');
  const uNoSlash = rstrip(platformUrl, '/');
  const uNoKas = uNoSlash.endsWith('/kas') ? uNoSlash.slice(0, -4) : uNoSlash;

  const platform = new PlatformClient({ authProvider, platformUrl: uNoKas });

  let response: GetAttributeValuesByFqnsResponse;
  try {
    response = await platform.v1.attributes.getAttributeValuesByFqns({
      fqns,
      withValue: {
        withKeyAccessGrants: true,
        withAttribute: {
          withKeyAccessGrants: true,
        },
      },
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
    // TODO: update the mapping
    values.push({
      id: value.id,
      attribute: value.attribute as never,
      value: value.value,
      grants: value.grants as never,
      fqn: value.fqn,
      active: value.active,
      subjectMappings: value.subjectMappings,
      metadata: value.metadata as never,
    });
  }
  return values;
}
