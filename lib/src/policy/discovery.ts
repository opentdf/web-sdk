import { AttributeNotFoundError, ConfigurationError, NetworkError } from '../errors.js';
import { type AuthProvider } from '../auth/auth.js';
import { extractRpcErrorMessage, validateSecureUrl } from '../utils.js';
import { PlatformClient } from '../platform.js';
import type { Attribute } from '../platform/policy/objects_pb.js';

// Caps the pagination loop in listAttributes. 10 pages × 1000 records = 10,000
// attributes maximum, which is generous for browser use while preventing runaway
// memory growth if a server repeatedly returns a non-zero next_offset.
const MAX_LIST_ATTRIBUTES_PAGES = 10;

// Number of attributes to request per page. Matches the platform's default
// (ListRequestLimitDefault = 1000) so behavior is stable regardless of server config.
const LIST_ATTRIBUTES_PAGE_SIZE = 1000;

// Matches the server-side proto constraint: GetAttributeValuesByFqnsRequest has
// max_items: 250 on the fqns field, so the client rejects oversized requests
// locally instead of receiving a cryptic server validation error.
const MAX_VALIDATE_FQNS = 250;

// Attribute value FQN format: https://<namespace>/attr/<name>/value/<value>
// Restricts to safe URL characters to prevent XSS via FQNs in error messages
const ATTRIBUTE_VALUE_FQN_RE =
  /^https?:\/\/[a-zA-Z0-9._~%-]+\/attr\/[a-zA-Z0-9._~%-]+\/value\/[a-zA-Z0-9._~%-]+$/i;

// Attribute-level FQN format: https://<namespace>/attr/<name>  (no /value/ segment)
// Restricts to safe URL characters to prevent XSS via FQNs in error messages
const ATTRIBUTE_FQN_RE = /^https?:\/\/[a-zA-Z0-9._~%-]+\/attr\/[a-zA-Z0-9._~%-]+$/i;

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
  if (!validateSecureUrl(platformUrl)) {
    throw new ConfigurationError('platformUrl must use HTTPS protocol');
  }
  const platform = new PlatformClient({ authProvider, platformUrl });
  const result: Attribute[] = [];
  let nextOffset = 0;

  for (let pages = 0; pages < MAX_LIST_ATTRIBUTES_PAGES; pages++) {
    let resp;
    try {
      resp = await platform.v1.attributes.listAttributes({
        namespace: namespace ?? '',
        pagination: { offset: nextOffset, limit: LIST_ATTRIBUTES_PAGE_SIZE },
      });
    } catch (e) {
      throw new NetworkError(`[ListAttributes] ${extractRpcErrorMessage(e)}`);
    }

    result.push(...resp.attributes);
    nextOffset = resp.pagination?.nextOffset ?? 0;
    if (nextOffset === 0) {
      return result;
    }
  }

  throw new ConfigurationError(
    `listAttributes returned more than ${MAX_LIST_ATTRIBUTES_PAGES * LIST_ATTRIBUTES_PAGE_SIZE} attributes. Use the namespace parameter to narrow results.`
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

  if (!validateSecureUrl(platformUrl)) {
    throw new ConfigurationError('platformUrl must use HTTPS protocol');
  }

  if (fqns.length > MAX_VALIDATE_FQNS) {
    throw new ConfigurationError(
      `too many attribute FQNs: ${fqns.length} exceeds maximum of ${MAX_VALIDATE_FQNS}`
    );
  }

  for (const fqn of fqns) {
    if (!ATTRIBUTE_VALUE_FQN_RE.test(fqn)) {
      throw new ConfigurationError('invalid attribute value FQN format');
    }
  }

  const platform = new PlatformClient({ authProvider, platformUrl });
  let resp;
  try {
    resp = await platform.v1.attributes.getAttributeValuesByFqns({ fqns });
  } catch (e) {
    throw new NetworkError(`[GetAttributeValuesByFqns] ${extractRpcErrorMessage(e)}`);
  }

  const found = resp.fqnAttributeValues;
  const missing = fqns.filter((fqn) => !(fqn in found));
  if (missing.length > 0) {
    throw new AttributeNotFoundError(`attribute not found: ${missing.length} FQN(s) missing`);
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
  if (!value) {
    throw new ConfigurationError('attribute value must not be empty');
  }

  if (!validateSecureUrl(platformUrl)) {
    throw new ConfigurationError('platformUrl must use HTTPS protocol');
  }

  if (!ATTRIBUTE_FQN_RE.test(attributeFqn)) {
    throw new ConfigurationError('invalid attribute FQN format');
  }

  const platform = new PlatformClient({ authProvider, platformUrl });
  let resp;
  try {
    resp = await platform.v1.attributes.getAttribute({
      identifier: { case: 'fqn', value: attributeFqn },
    });
  } catch {
    throw new AttributeNotFoundError('attribute not found');
  }

  const vals = resp.attribute?.values ?? [];
  if (vals.length === 0) {
    // Dynamic attribute — any value is permitted.
    return;
  }

  const match = vals.some((v) => v.value.toLowerCase() === value.toLowerCase());
  if (!match) {
    throw new AttributeNotFoundError(
      `value "${value}" is not permitted for attribute ${attributeFqn}`
    );
  }
}

