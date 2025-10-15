import { NetworkError } from '../errors.js';
import { AuthProvider } from '../auth/auth.js';
import { extractRpcErrorMessage, getPlatformUrlFromKasEndpoint } from '../utils.js';
import { PlatformClient } from '../platform.js';
import { Value } from './attributes.js';
import { GetAttributeValuesByFqnsResponse } from '../platform/policy/attributes/attributes_pb.js';

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
