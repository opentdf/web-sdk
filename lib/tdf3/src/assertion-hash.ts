/**
 * Assertion hashing (ZTDF assertions contract, Sections 3 and 4).
 *
 * Internal: the public surface is `computeAssertionHash` and `hash` in
 * `assertions.ts`. This module imports nothing from there, so the two do not
 * form a runtime import cycle.
 */
import { hex } from '../../src/encodings/index.js';
import { AssertionVerificationError, type AssertionFailureReason } from '../../src/errors.js';
import { type CryptoService } from './crypto/declarations.js';
import { DefaultCryptoService } from './crypto/index.js';
import { canonicalJson, scanStrictJson } from './strict-json.js';

export type JsonObject = Record<string, unknown>;

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function hasOwn(o: object, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, name);
}

/** Throw an {@link AssertionVerificationError}. */
export function fail(
  reason: AssertionFailureReason,
  detail: string,
  assertionId?: string,
  cause?: unknown
): never {
  throw new AssertionVerificationError(
    reason,
    detail,
    assertionId,
    cause instanceof Error ? cause : undefined
  );
}

/**
 * SHA-256 over the JCS form of `a` without its top-level `binding` member.
 * Every other member, at any depth, is hashed.
 */
export async function assertionDigest(
  a: JsonObject,
  cryptoService: CryptoService
): Promise<Uint8Array> {
  // Object.fromEntries defines data properties, so a member named
  // `__proto__` stays an ordinary member instead of setting the prototype.
  const unbound = Object.fromEntries(Object.entries(a).filter(([name]) => name !== 'binding'));
  return cryptoService.digest('SHA-256', new TextEncoder().encode(canonicalJson(unbound)));
}

/**
 * Parse the raw text of one assertion wire object under spec Section 3:
 * duplicate members, case variants at the assertion, statement, and binding
 * levels, and I-JSON.
 */
export function parseAssertionWireJson(wireJson: string): JsonObject {
  if (typeof wireJson !== 'string') {
    fail('invalid-json', 'assertion wire JSON must be a string');
  }
  const scan = scanStrictJson(wireJson, 'assertion');
  if (scan.failure) {
    fail(scan.failure.reason, scan.failure.detail, scan.failure.assertionId);
  }
  if (scan.syntaxError !== undefined) {
    fail('invalid-json', `assertion is not valid JSON: ${scan.syntaxError}`);
  }
  const parsed = JSON.parse(wireJson) as unknown;
  if (!isJsonObject(parsed)) {
    fail('invalid-json', 'an assertion must be a JSON object');
  }
  return parsed;
}

/**
 * The exact `id` of an assertion (spec Section 3.3): its own `id` member, a
 * nonempty string, compared without trimming, folding, or normalization.
 */
export function assertionId(a: unknown): string {
  if (isJsonObject(a) && hasOwn(a, 'id')) {
    const { id } = a;
    if (typeof id === 'string' && id !== '') {
      return id;
    }
  }
  return fail('invalid-id', 'assertion id must be a nonempty string');
}

/** Lowercase hex SHA-256 of an assertion as received, minus its top-level `binding`. */
export async function hashAssertion(
  a: JsonObject,
  id: string | undefined,
  cryptoService: CryptoService
): Promise<{ hex: string; bytes: Uint8Array }> {
  let bytes: Uint8Array;
  try {
    bytes = await assertionDigest(a, cryptoService);
  } catch (e) {
    if (e instanceof AssertionVerificationError) {
      throw e;
    }
    return fail('invalid-json', 'assertion cannot be canonicalized', id, e);
  }
  return { hex: hex.encodeArrayBuffer(bytes), bytes };
}

/**
 * Parse one assertion wire object under spec Section 3, check its `id`, and
 * return `lowercase-hex(SHA-256(JCS(assertion minus binding)))`.
 */
export async function computeAssertionHash(
  wireJson: string,
  cryptoService: CryptoService = DefaultCryptoService
): Promise<string> {
  const a = parseAssertionWireJson(wireJson);
  const id = assertionId(a);
  return (await hashAssertion(a, id, cryptoService)).hex;
}
