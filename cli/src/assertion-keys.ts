import { readFile } from 'node:fs/promises';
import type * as assertions from '@opentdf/sdk/assertions';
import { CLIError } from './logger.js';

const asError = (value: unknown): Error =>
  value instanceof Error ? value : new Error(String(value));

// TextDecoder, like Blob.text(), removes a leading UTF-8 BOM. readFile's
// 'utf8' string decoding leaves it in place, which JSON.parse rejects.
export const readJsonFileText = async (path: string): Promise<string> =>
  new TextDecoder().decode(await readFile(path));

/**
 * Convert a key from its JSON form to what the SDK expects: HS256 keys are the
 * UTF-8 bytes of the string, RS256 keys stay PEM strings.
 */
export function correctAssertionKeys({ alg, key }: assertions.AssertionKey): string | Uint8Array {
  if (alg === 'HS256') {
    if (typeof key !== 'string') {
      throw new CLIError('CRITICAL', 'HS256 key must be a string');
    }
    return new TextEncoder().encode(key);
  } else if (alg === 'RS256') {
    if (typeof key !== 'string') {
      throw new CLIError('CRITICAL', 'RS256 key must be a PEM string');
    }
    return key;
  }
  throw new CLIError('CRITICAL', `Unsupported signing key algorithm: ${alg}`);
}

// Key file problems are configuration errors, reported with the same reason
// code the SDK uses for an invalid configured key.
const configurationError = (message: string, cause?: Error) =>
  new CLIError('CRITICAL', `${message} (reason=configuration-error)`, cause);

function convertKey(name: string, assertionKey: unknown): assertions.AssertionKey {
  if (typeof assertionKey !== 'object' || assertionKey === null || Array.isArray(assertionKey)) {
    throw configurationError(`Invalid assertion for ${name}: Must be an object`);
  }
  const { alg, key } = assertionKey as Partial<assertions.AssertionKey>;
  if (typeof alg !== 'string') {
    throw configurationError(`Invalid assertion for ${name}: Missing or invalid 'key' or 'alg'`);
  }
  try {
    return { alg, key: correctAssertionKeys({ alg, key } as assertions.AssertionKey) };
  } catch (err) {
    throw configurationError(`Issue converting assertion key from string: ${asError(err).message}`);
  }
}

const isUnset = (value: unknown) => value === undefined || value === null || value === '';

/** True for a default key that is not configured: absent, null, `{}`, or no alg and no key. */
function isAbsentKey(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const { alg, key } = value as Record<string, unknown>;
  return (
    Object.keys(value).every((m) => m === 'alg' || m === 'key') && isUnset(alg) && isUnset(key)
  );
}

const TOP_LEVEL_MEMBERS = ['keys', 'Keys', 'defaultKey', 'DefaultKey'];

/**
 * Parse the assertion verification keys option: inline JSON, or the path to a
 * JSON file, of the form
 *
 * ```json
 * { "keys": { "<id>": { "alg": "RS256", "key": "<PEM or secret>" } },
 *   "defaultKey": { "alg": "HS256", "key": "<secret>" } }
 * ```
 *
 * `Keys` and `DefaultKey` are accepted as spellings too; any other top-level
 * member is an error. The default key is used for assertions without an entry
 * in `keys`; a default key with no alg and no key counts as not configured.
 */
export async function parseAssertionVerificationKeys(
  s: string
): Promise<assertions.AssertionVerificationKeys> {
  let u: unknown;
  try {
    u = JSON.parse(s);
  } catch (err) {
    // try as file name:
    try {
      u = JSON.parse(await readJsonFileText(s));
    } catch (err2) {
      const cause = asError(err2);
      throw new CLIError(
        'CRITICAL',
        `Failed to open/parse assertion verification keys as string or file path ${asError(err).message}`,
        cause
      );
    }
  }
  if (typeof u !== 'object' || u === null || Array.isArray(u)) {
    throw configurationError('Invalid input: The input must be an object');
  }
  const input = u as Record<string, unknown>;
  const unknown = Object.keys(input).filter((m) => !TOP_LEVEL_MEMBERS.includes(m));
  if (unknown.length) {
    throw configurationError(
      `Invalid assertion verification keys: unknown member ${JSON.stringify(unknown[0])}; expected keys and defaultKey`
    );
  }
  const pick = (...names: string[]): unknown => {
    for (const name of names) {
      const value = input[name];
      if (value !== undefined && value !== null) {
        return value;
      }
    }
    return undefined;
  };
  const rawKeys = pick('Keys', 'keys');
  const rawDefaultKey = pick('DefaultKey', 'defaultKey');
  if (
    rawKeys === undefined
      ? rawDefaultKey === undefined
      : typeof rawKeys !== 'object' || Array.isArray(rawKeys)
  ) {
    throw configurationError('Invalid input: invalid structure of assertionVerificationKeys');
  }
  // Object.fromEntries defines data properties, so an id such as `__proto__`
  // stays an ordinary entry.
  const result: assertions.AssertionVerificationKeys = {
    Keys: Object.fromEntries(
      Object.entries((rawKeys ?? {}) as Record<string, unknown>).map(([name, value]) => [
        name,
        convertKey(name, value),
      ])
    ),
  };
  if (!isAbsentKey(rawDefaultKey)) {
    result.DefaultKey = convertKey('defaultKey', rawDefaultKey);
  }
  return result;
}
