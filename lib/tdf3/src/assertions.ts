import { canonicalizeEx } from 'json-canonicalize';
import { type KeyLike, SignJWT, jwtVerify } from 'jose';
import { base64, hex } from '../../src/encodings/index.js';
import { ConfigurationError, IntegrityError, InvalidFileError } from '../../src/errors.js';

export type AssertionKeyAlg = 'RS256' | 'HS256';
export type AssertionType = 'handling' | 'other';
export type Scope = 'tdo' | 'payload';
export type AppliesToState = 'encrypted' | 'unencrypted';
export type BindingMethod = 'jws';

// Statement type
export type Statement = {
  format: string;
  schema: string;
  value: string;
};

// Binding type
export type Binding = {
  method: string;
  signature: string;
};

// Assertion type
export type Assertion = {
  id: string;
  type: AssertionType;
  scope: Scope;
  appliesToState?: AppliesToState;
  statement: Statement;
  binding: Binding;
};

export type AssertionPayload = {
  assertionHash: string;
  assertionSig: string;
};

/**
 * Computes the SHA-256 hash of the assertion object, excluding the 'binding' and 'hash' properties.
 *
 * @returns the hexadecimal string representation of the hash
 */
export async function hash(a: Assertion): Promise<string> {
  const result = canonicalizeEx(a, { exclude: ['binding', 'hash', 'sign', 'verify'] });

  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(result));
  return hex.encodeArrayBuffer(hash);
}

/**
 * Signs the given hash and signature using the provided key and sets the binding method and signature.
 *
 * @param hash - The hash to be signed.
 * @param sig - The signature to be signed.
 * @param {AssertionKey} key - The key used for signing.
 * @returns {Promise<void>} A promise that resolves when the signing is complete.
 */
async function sign(
  thiz: Assertion,
  assertionHash: string,
  sig: string,
  key: AssertionKey
): Promise<Assertion> {
  const payload: AssertionPayload = {
    assertionHash,
    assertionSig: sig,
  };

  let token: string;
  try {
    token = await new SignJWT(payload).setProtectedHeader({ alg: key.alg }).sign(key.key);
  } catch (error) {
    throw new ConfigurationError(`Signing assertion failed: ${error.message}`, error);
  }
  thiz.binding.method = 'jws';
  thiz.binding.signature = token;
  return thiz;
}

// a function that takes an unknown or any object and asserts that it is or is not an AssertionConfig object
export function isAssertionConfig(obj: unknown): obj is AssertionConfig {
  return (
    !!obj &&
    typeof obj === 'object' &&
    'id' in obj &&
    typeof obj.id === 'string' &&
    'type' in obj &&
    (obj.type === 'handling' || obj.type === 'other') &&
    'scope' in obj &&
    (obj.scope === 'tdo' || obj.scope === 'payload') &&
    'appliesToState' in obj &&
    (obj.appliesToState === 'encrypted' || obj.appliesToState === 'unencrypted') &&
    'statement' in obj &&
    !!obj.statement &&
    typeof obj.statement === 'object' &&
    'format' in obj.statement &&
    'schema' in obj.statement &&
    'value' in obj.statement
  );
}

/**
 * Verifies the signature of the assertion using the provided key.
 *
 * @param {AssertionKey} key - The key used for verification.
 * @returns {Promise<[string, string]>} A promise that resolves to a tuple containing the assertion hash and signature.
 * @throws {Error} If the verification fails.
 */
export async function verify(
  thiz: Assertion,
  aggregateHash: Uint8Array,
  key: AssertionKey,
  isLegacyTDF: boolean
): Promise<void> {
  let payload: AssertionPayload;
  try {
    const uj = await jwtVerify(thiz.binding.signature, key.key, {
      algorithms: [key.alg],
    });
    payload = uj.payload as AssertionPayload;
  } catch (error) {
    throw new InvalidFileError(`Verifying assertion failed: ${error.message}`, error);
  }
  const { assertionHash, assertionSig } = payload;

  // Get the hash of the assertion
  const hashOfAssertion = await hash(thiz);

  // check if assertionHash is same as hashOfAssertion
  if (hashOfAssertion !== assertionHash) {
    throw new IntegrityError('Assertion hash mismatch');
  }

  let encodedHash: string;
  if (isLegacyTDF) {
    const aggregateHashAsStr = new TextDecoder('utf-8').decode(aggregateHash);
    const combinedHash = aggregateHashAsStr + hashOfAssertion;
    encodedHash = base64.encode(combinedHash);
  } else {
    const combinedHash = concatenateUint8Arrays(
      aggregateHash,
      new Uint8Array(hex.decodeArrayBuffer(assertionHash))
    );
    encodedHash = base64.encodeArrayBuffer(combinedHash);
  }

  // check if assertionSig is same as encodedHash
  if (assertionSig !== encodedHash) {
    throw new IntegrityError('Failed integrity check on assertion signature');
  }
}

/**
 * Creates an Assertion object with the specified properties.
 */
export async function CreateAssertion(
  aggregateHash: Uint8Array,
  assertionConfig: AssertionConfig
): Promise<Assertion> {
  if (!assertionConfig.signingKey) {
    throw new ConfigurationError('Assertion signing key is required');
  }

  const a: Assertion = {
    id: assertionConfig.id,
    type: assertionConfig.type,
    scope: assertionConfig.scope,
    appliesToState: assertionConfig.appliesToState,
    statement: assertionConfig.statement,
    // empty binding
    binding: { method: '', signature: '' },
  };

  const assertionHash = await hash(a);
  const combinedHash = concatenateUint8Arrays(
    aggregateHash,
    new Uint8Array(hex.decodeArrayBuffer(assertionHash))
  );
  const encodedHash = base64.encodeArrayBuffer(combinedHash);

  return await sign(a, assertionHash, encodedHash, assertionConfig.signingKey);
}

export type AssertionKey = {
  alg: AssertionKeyAlg;
  key: KeyLike | Uint8Array;
};

// AssertionConfig is a shadow of Assertion with the addition of the signing key.
// It is used on creation of the assertion.
export type AssertionConfig = {
  id: string;
  type: AssertionType;
  scope: Scope;
  appliesToState: AppliesToState;
  statement: Statement;
  signingKey?: AssertionKey;
};

// AssertionVerificationKeys represents the verification keys for assertions.
export type AssertionVerificationKeys = {
  DefaultKey?: AssertionKey;
  Keys: Record<string, AssertionKey>;
};

function concatenateUint8Arrays(array1: Uint8Array, array2: Uint8Array): Uint8Array {
  const combinedLength = array1.length + array2.length;
  const combinedArray = new Uint8Array(combinedLength);

  combinedArray.set(array1, 0);
  combinedArray.set(array2, array1.length);

  return combinedArray;
}
