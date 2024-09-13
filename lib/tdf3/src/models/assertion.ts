import { canonicalizeEx } from 'json-canonicalize';
import { SignJWT, jwtVerify } from 'jose';
import { AssertionKey } from './../client/AssertionConfig.js';

export type AssertionType = 'handling' | 'other';
export type Scope = 'tdo' | 'payload';
export type AppliesToState = 'encrypted' | 'unencrypted';
export type BindingMethod = 'jws';

const kAssertionHash = 'assertionHash';
const kAssertionSignature = 'assertionSig';

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
  hash: () => Promise<string>;
  sign: (hash: string, sig: string, key: AssertionKey) => Promise<void>;
  verify: (key: AssertionKey) => Promise<[string, string]>;
};

/**
 * Computes the SHA-256 hash of the assertion object, excluding the 'binding' and 'hash' properties.
 *
 * @returns {Promise<string>} A promise that resolves to the hexadecimal string representation of the hash.
 */
export async function hash(this: Assertion): Promise<string> {
  const result = canonicalizeEx(this, { exclude: ['binding', 'hash'] });
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(result));
  return Buffer.from(hash).toString('hex');
}

/**
 * Signs the given hash and signature using the provided key and sets the binding method and signature.
 *
 * @param {string} hash - The hash to be signed.
 * @param {string} sig - The signature to be signed.
 * @param {AssertionKey} key - The key used for signing.
 * @returns {Promise<void>} A promise that resolves when the signing is complete.
 */
export async function sign(this: Assertion, assertionHash: string, sig: string, key: AssertionKey): Promise<void> {
  const payload: any = {};
  payload[kAssertionHash] = hash;
  payload[kAssertionSignature] = sig;

  try {
    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: key.alg })
      .sign(key.key);

    this.binding.method = 'jws';
    this.binding.signature = token;
  } catch (error) {
    throw new Error(`Signing assertion failed: ${error.message}`);
  }
}

/**
 * Verifies the signature of the assertion using the provided key.
 *
 * @param {AssertionKey} key - The key used for verification.
 * @returns {Promise<[string, string]>} A promise that resolves to a tuple containing the assertion hash and signature.
 * @throws {Error} If the verification fails.
 */
export async function verify(this: Assertion, key: AssertionKey): Promise<[string, string]> {
  try {
    const { payload } = await jwtVerify(this.binding.signature, key.key, {
      algorithms: [key.alg],
    });

    return [payload[kAssertionHash] as string, payload[kAssertionSignature] as string];
  } catch (error) {
    throw new Error(`Verifying assertion failed: ${error.message}`);
  }
}

/**
 * Creates an Assertion object with the specified properties.
 *
 * @param {string} id - The unique identifier for the assertion.
 * @param {AssertionType} type - The type of the assertion (e.g., 'handling', 'other').
 * @param {Scope} scope - The scope of the assertion (e.g., 'tdo', 'payload').
 * @param {Statement} statement - The statement associated with the assertion.
 * @param {Binding} binding - The binding method and signature for the assertion.
 * @param {AppliesToState} [appliesToState] - The state to which the assertion applies (optional).
 * @returns {Assertion} The created Assertion object.
 */
export function CreateAssertion(
  id: string,
  type: AssertionType,
  scope: Scope,
  statement: Statement,
  appliesToState?: AppliesToState
): Assertion {
  return {
    id,
    type,
    scope,
    appliesToState,
    statement,
    binding: { method: '', signature: '' },
    hash,
    sign,
    verify
  };
}