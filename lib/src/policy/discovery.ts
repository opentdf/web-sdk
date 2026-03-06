import { ConnectError, Code } from '@connectrpc/connect';
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
 * Reports whether the attribute definition identified by `attributeFqn` exists on the platform.
 *
 * `attributeFqn` should be an attribute-level FQN (no `/value/` segment):
 * `https://<namespace>/attr/<attribute_name>`
 *
 * @param platformUrl The platform base URL.
 * @param authProvider An auth provider for the request.
 * @param attributeFqn The attribute-level FQN to check.
 * @returns `true` if the attribute exists, `false` if it does not.
 * @throws {@link ConfigurationError} if the FQN format is invalid or the URL is insecure.
 * @throws {@link NetworkError} if a non-not-found service error occurs.
 */
export async function attributeExists(
  platformUrl: string,
  authProvider: AuthProvider,
  attributeFqn: string
): Promise<boolean> {
  if (!validateSecureUrl(platformUrl)) {
    throw new ConfigurationError('platformUrl must use HTTPS protocol');
  }

  if (!ATTRIBUTE_FQN_RE.test(attributeFqn)) {
    throw new ConfigurationError('invalid attribute FQN format');
  }

  const platform = new PlatformClient({ authProvider, platformUrl });
  try {
    await platform.v1.attributes.getAttribute({
      identifier: { case: 'fqn', value: attributeFqn },
    });
    return true;
  } catch (e) {
    if (e instanceof ConnectError && e.code === Code.NotFound) {
      return false;
    }
    throw new NetworkError(`[GetAttribute] ${extractRpcErrorMessage(e)}`);
  }
}

/**
 * Reports whether the attribute value FQN exists on the platform.
 *
 * `valueFqn` should be a full attribute value FQN (with `/value/` segment):
 * `https://<namespace>/attr/<attribute_name>/value/<value>`
 *
 * @param platformUrl The platform base URL.
 * @param authProvider An auth provider for the request.
 * @param valueFqn The attribute value FQN to check.
 * @returns `true` if the value exists, `false` if it does not.
 * @throws {@link ConfigurationError} if the FQN format is invalid or the URL is insecure.
 * @throws {@link NetworkError} if a service error occurs.
 */
export async function attributeValueExists(
  platformUrl: string,
  authProvider: AuthProvider,
  valueFqn: string
): Promise<boolean> {
  if (!validateSecureUrl(platformUrl)) {
    throw new ConfigurationError('platformUrl must use HTTPS protocol');
  }

  if (!ATTRIBUTE_VALUE_FQN_RE.test(valueFqn)) {
    throw new ConfigurationError('invalid attribute value FQN format');
  }

  const platform = new PlatformClient({ authProvider, platformUrl });
  let resp;
  try {
    resp = await platform.v1.attributes.getAttributeValuesByFqns({ fqns: [valueFqn] });
  } catch (e) {
    throw new NetworkError(`[GetAttributeValuesByFqns] ${extractRpcErrorMessage(e)}`);
  }

  return valueFqn in resp.fqnAttributeValues;
}
