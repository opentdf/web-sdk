import { InvalidFileError } from './errors.js';

/** Any value `JSON.parse` can return. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * `T` as it appears before validation: the shape we hope for, but every
 * property may be absent and every leaf may be any JSON value, because the
 * bytes came from a file we did not write.
 *
 * Mutable, because the object is a scratch result of `JSON.parse` that nobody
 * else holds a reference to.
 *
 * This widens *leaves*; containers keep their structure. It does not prove that
 * `m.encryptionInformation` is an object, only that reaching a string out of it
 * requires a check. Code that walks into a container still needs a runtime
 * guard — see `asManifest`.
 */
export type Unvalidated<T> = T extends readonly (infer E)[]
  ? Unvalidated<E>[]
  : T extends object
    ? { -readonly [K in keyof T]?: Unvalidated<T[K]> }
    : JsonValue;

/**
 * Narrow a parsed value to a JSON object, naming the member that wasn't one.
 * `path` is for the error message only; it is where the value came from.
 */
export function asRecord(value: JsonValue | undefined, path: string): { [key: string]: JsonValue } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new InvalidFileError(`[${path}] is not an object`);
  }
  return value;
}

/** Narrow a parsed value to a string, naming the member that wasn't one. */
export function asString(value: JsonValue | undefined, path: string): string {
  if (typeof value !== 'string') {
    throw new InvalidFileError(`[${path}] is not a string`);
  }
  return value;
}

/** As {@link asString}, but absent and `null` both read as absent. */
export function asOptionalString(value: JsonValue | undefined, path: string): string | undefined {
  return value === undefined || value === null ? undefined : asString(value, path);
}
