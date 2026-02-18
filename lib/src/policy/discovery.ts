import { AttributeNotFoundError, ConfigurationError, NetworkError } from '../errors.js';
import { type AuthProvider } from '../auth/auth.js';
import { extractRpcErrorMessage, validateSecureUrl } from '../utils.js';
import { PlatformClient } from '../platform.js';
import type { Attribute } from '../platform/policy/objects_pb.js';
import type { Entity } from '../platform/authorization/authorization_pb.js';

// Caps the pagination loop in listAttributes to prevent unbounded memory growth
// if a server repeatedly returns a non-zero next_offset.
const MAX_LIST_ATTRIBUTES_PAGES = 1000;

// Matches the server-side limit on GetAttributeValuesByFqns so callers get a
// clear local error instead of a cryptic server rejection.
const MAX_VALIDATE_FQNS = 250;

// Attribute value FQN format: https://<namespace>/attr/<name>/value/<value>
const ATTRIBUTE_VALUE_FQN_RE = /^https?:\/\/[^/]+\/attr\/[^/]+\/value\/[^/]+$/i;

// Attribute-level FQN format: https://<namespace>/attr/<name>  (no /value/ segment)
const ATTRIBUTE_FQN_RE = /^https?:\/\/[^/]+\/attr\/[^/]+$/i;

/**
 * Returns all active attributes available on the platform, auto-paginating through all results.
 * An optional namespace name or ID may be provided to filter results.
 *
 * Use this before calling `createZTDF()` to see what attributes are available for data tagging.
 *
 * @param platformUrl The platform base URL.
 * @param authProvider An auth provider for the request.
 * @param namespace Optional namespace name or ID to filter results.
 * @returns All active {@link Attribute} objects on the platform.
 *
 * @example
 * ```ts
 * const attrs = await listAttributes(platformUrl, authProvider);
 * for (const a of attrs) {
 *   console.log(a.fqn);
 * }
 * ```
 */
export async function listAttributes(
  platformUrl: string,
  authProvider: AuthProvider,
  namespace?: string
): Promise<Attribute[]> {
  const platform = new PlatformClient({ authProvider, platformUrl });
  const result: Attribute[] = [];
  let nextOffset = 0;

  for (let pages = 0; pages < MAX_LIST_ATTRIBUTES_PAGES; pages++) {
    let resp;
    try {
      resp = await platform.v1.attributes.listAttributes({
        namespace: namespace ?? '',
        pagination: { offset: nextOffset, limit: 0 },
      });
    } catch (e) {
      throw new NetworkError(`[${platformUrl}] [ListAttributes] ${extractRpcErrorMessage(e)}`);
    }

    if (pages === 0 && (resp.pagination?.total ?? 0) > 0) {
      result.length = 0; // reset before push to avoid over-allocation (pre-hint not available in JS arrays natively)
    }

    result.push(...resp.attributes);
    nextOffset = resp.pagination?.nextOffset ?? 0;
    if (nextOffset === 0) {
      return result;
    }
  }

  throw new ConfigurationError(
    `listing attributes: exceeded maximum page limit (${MAX_LIST_ATTRIBUTES_PAGES})`
  );
}

/**
 * Checks that all provided attribute value FQNs exist on the platform.
 * Validates FQN format first, then verifies existence via the platform API.
 *
 * Use this before `createZTDF()` to catch missing or misspelled attributes early
 * instead of discovering the problem at decryption time.
 *
 * @param platformUrl The platform base URL.
 * @param authProvider An auth provider for the request.
 * @param fqns Attribute value FQNs to validate, in the form
 *   `https://<namespace>/attr/<name>/value/<value>`.
 * @throws {@link AttributeNotFoundError} if any FQNs are not found on the platform.
 * @throws {@link ConfigurationError} if the FQN format is invalid or there are too many FQNs.
 *
 * @example
 * ```ts
 * await validateAttributes(platformUrl, authProvider, [
 *   'https://opentdf.io/attr/department/value/marketing',
 * ]);
 * // Safe to encrypt — all attributes confirmed present
 * ```
 */
export async function validateAttributes(
  platformUrl: string,
  authProvider: AuthProvider,
  fqns: string[]
): Promise<void> {
  if (!fqns || fqns.length === 0) {
    return;
  }

  if (fqns.length > MAX_VALIDATE_FQNS) {
    throw new ConfigurationError(
      `too many attribute FQNs: ${fqns.length} exceeds maximum of ${MAX_VALIDATE_FQNS}`
    );
  }

  for (const fqn of fqns) {
    if (!ATTRIBUTE_VALUE_FQN_RE.test(fqn)) {
      throw new ConfigurationError(`invalid attribute value FQN "${fqn}"`);
    }
  }

  const platform = new PlatformClient({ authProvider, platformUrl });
  let resp;
  try {
    resp = await platform.v1.attributes.getAttributeValuesByFqns({ fqns });
  } catch (e) {
    throw new NetworkError(
      `[${platformUrl}] [GetAttributeValuesByFqns] ${extractRpcErrorMessage(e)}`
    );
  }

  const found = resp.fqnAttributeValues;
  const missing = fqns.filter((fqn) => !(fqn in found));
  if (missing.length > 0) {
    throw new AttributeNotFoundError(`attribute not found: ${missing.join(', ')}`);
  }
}

/**
 * Checks that a single attribute value FQN is valid in format and exists on the platform.
 *
 * This is a convenience wrapper around {@link validateAttributes} for the single-FQN case.
 *
 * @param platformUrl The platform base URL.
 * @param authProvider An auth provider for the request.
 * @param fqn The attribute value FQN to validate.
 * @throws {@link AttributeNotFoundError} if the FQN does not exist on the platform.
 * @throws {@link ConfigurationError} if the FQN format is invalid.
 */
export async function validateAttributeExists(
  platformUrl: string,
  authProvider: AuthProvider,
  fqn: string
): Promise<void> {
  return validateAttributes(platformUrl, authProvider, [fqn]);
}

/**
 * Checks that `value` is a permitted value for the attribute identified by `attributeFqn`.
 * Handles both enumerated and dynamic attribute types:
 * - Enumerated attributes: `value` must match one of the pre-registered values (case-insensitive).
 * - Dynamic attributes (no pre-registered values): any value is accepted.
 *
 * @param platformUrl The platform base URL.
 * @param authProvider An auth provider for the request.
 * @param attributeFqn The attribute-level FQN, e.g. `https://example.com/attr/clearance`.
 * @param value The candidate value string, e.g. `secret`.
 * @throws {@link AttributeNotFoundError} if the attribute does not exist, or if the attribute
 *   is enumerated and `value` is not in the allowed set.
 * @throws {@link ConfigurationError} if the FQN format is invalid.
 *
 * @example
 * ```ts
 * await validateAttributeValue(platformUrl, authProvider, 'https://opentdf.io/attr/clearance', 'secret');
 * // Safe to use — value confirmed valid for this attribute
 * ```
 */
export async function validateAttributeValue(
  platformUrl: string,
  authProvider: AuthProvider,
  attributeFqn: string,
  value: string
): Promise<void> {
  if (!ATTRIBUTE_FQN_RE.test(attributeFqn)) {
    throw new ConfigurationError(`invalid attribute FQN "${attributeFqn}"`);
  }

  const platform = new PlatformClient({ authProvider, platformUrl });
  let resp;
  try {
    resp = await platform.v1.attributes.getAttribute({
      identifier: { case: 'fqn', value: attributeFqn },
    });
  } catch (e) {
    throw new AttributeNotFoundError(`attribute not found: ${attributeFqn}`);
  }

  const vals = resp.attribute?.values ?? [];
  if (vals.length === 0) {
    // Dynamic attribute — any value is permitted.
    return;
  }

  const match = vals.some((v) => v.value.toLowerCase() === value.toLowerCase());
  if (!match) {
    throw new AttributeNotFoundError(
      `attribute not found: value "${value}" not permitted for attribute ${attributeFqn}`
    );
  }
}

/**
 * Returns the attribute value FQNs assigned to an entity (PE or NPE).
 *
 * Use this to inspect what attributes a user, service account, or other entity has been
 * granted before making authorization decisions or constructing access policies.
 *
 * @param platformUrl The platform base URL.
 * @param authProvider An auth provider for the request.
 * @param entity The entity to look up. Must not be null/undefined.
 * @returns Attribute value FQNs assigned to the entity, or an empty array if none.
 * @throws {@link ConfigurationError} if entity is null or undefined.
 *
 * @example
 * ```ts
 * import type { Entity } from '@opentdf/sdk';
 *
 * const entity: Entity = { id: 'e1', emailAddress: 'alice@example.com' };
 * const fqns = await getEntityAttributes(platformUrl, authProvider, entity);
 * console.log("alice's entitlements:", fqns);
 * ```
 */
export async function getEntityAttributes(
  platformUrl: string,
  authProvider: AuthProvider,
  entity: Entity
): Promise<string[]> {
  if (!entity) {
    throw new ConfigurationError('entity must not be null');
  }

  const platform = new PlatformClient({ authProvider, platformUrl });
  let resp;
  try {
    resp = await platform.v1.authorization.getEntitlements({ entities: [entity] });
  } catch (e) {
    throw new NetworkError(`[${platformUrl}] [GetEntitlements] ${extractRpcErrorMessage(e)}`);
  }

  const entityId = entity.id;
  for (const e of resp.entitlements) {
    if (e.entityId === entityId) {
      return e.attributeValueFqns;
    }
  }
  return [];
}
