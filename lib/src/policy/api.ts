import { NetworkError } from '../errors.js';
import { type AuthConfig, resolveInterceptors } from '../auth/interceptors.js';
import { extractRpcErrorMessage, getPlatformUrlFromKasEndpoint } from '../utils.js';
import { PlatformClient } from '../platform.js';
import { Value } from './attributes.js';
import {
  GetAttributeValuesByFqnsResponse,
  GetKeyMappingsByFqnsResponse,
} from '../platform/policy/attributes/attributes_pb.js';
import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import { AttributeSchema, ValueSchema } from '../platform/policy/objects_pb.js';

// Derives the attribute-level FQN from an attribute value FQN by dropping the
// `/value/<value>` segment (e.g. https://ns/attr/name/value/v -> https://ns/attr/name).
function attributeFqnFromValueFqn(valueFqn: string): string {
  return valueFqn.split('/value/')[0];
}

/**
 * Resolves attribute value FQNs to {@link Value}s carrying their effective mapped KAS
 * keys via the GetKeyMappingsByFqns RPC, the client-side key-split read path that
 * replaces the deprecated GetAttributeValuesByFqns during encrypt.
 *
 * Values with no mapped keys (e.g. configured only with legacy KAS grants) are
 * resolved through {@link attributeFQNsAsValues} so their grants still apply. Older
 * platforms that do not implement GetKeyMappingsByFqns fall back to the same helper.
 */
export async function attributeFQNsAsKeyMappings(
  platformUrl: string,
  auth: AuthConfig,
  ...fqns: string[]
): Promise<Value[]> {
  platformUrl = getPlatformUrlFromKasEndpoint(platformUrl);
  const platform = new PlatformClient({ interceptors: resolveInterceptors(auth), platformUrl });

  let response: GetKeyMappingsByFqnsResponse;
  try {
    response = await platform.v1.attributes.getKeyMappingsByFqns({ fqns });
  } catch (e) {
    if (e instanceof ConnectError && e.code === Code.Unimplemented) {
      return fetchAttributeFQNsAsValues(platform, platformUrl, fqns);
    }
    throw new NetworkError(`[${platformUrl}] [GetKeyMappingsByFqns] ${extractRpcErrorMessage(e)}`);
  }

  const values: Value[] = [];
  const legacyGrantFqns: string[] = [];
  // Iterate the requested FQNs (not the response map) so a value the server omits
  // still falls back rather than being silently dropped. The server normalizes
  // response keys to lower case (resolveValueFqns), so look them up lower-cased.
  for (const fqn of fqns) {
    const mapping = response.fqnKeyMappings[fqn.toLowerCase()];
    if (!mapping?.keys.length) {
      // No mapped keys (legacy-grant-only value, or omitted by the server); resolve
      // via the full attribute lookup, which also surfaces genuinely missing FQNs.
      legacyGrantFqns.push(fqn);
      continue;
    }
    values.push(
      create(ValueSchema, {
        fqn,
        kasKeys: mapping.keys,
        attribute: create(AttributeSchema, {
          fqn: attributeFqnFromValueFqn(fqn),
          rule: mapping.rule,
        }),
      })
    );
  }

  if (legacyGrantFqns.length) {
    values.push(...(await fetchAttributeFQNsAsValues(platform, platformUrl, legacyGrantFqns)));
  }

  return values;
}

// TODO KAS: go over web-sdk and remove policyEndpoint that is only defined to be used here
export async function attributeFQNsAsValues(
  platformUrl: string,
  auth: AuthConfig,
  ...fqns: string[]
): Promise<Value[]> {
  platformUrl = getPlatformUrlFromKasEndpoint(platformUrl);
  const platform = new PlatformClient({ interceptors: resolveInterceptors(auth), platformUrl });
  return fetchAttributeFQNsAsValues(platform, platformUrl, fqns);
}

// Resolves attribute value FQNs via GetAttributeValuesByFqns using an existing
// platform client, so callers (e.g. the key-mappings fallback) can reuse one client.
async function fetchAttributeFQNsAsValues(
  platform: PlatformClient,
  platformUrl: string,
  fqns: string[]
): Promise<Value[]> {
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
    let value = av.value;
    if (!value) {
      if (!av.attribute) {
        console.warn(`Missing attribute definition for [${fqn}]; is this a valid attribute?`);
        continue;
      }
      console.warn(`Missing value definition for [${fqn}]; using attribute definition only.`);

      value = create(ValueSchema, { attribute: av.attribute, fqn });
    } else if (av.attribute && !value?.attribute) {
      value.attribute = av.attribute;
    }

    values.push(value);
  }
  return values;
}
