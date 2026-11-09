/**
 * Verification-key selection and binding verification (ZTDF assertions
 * contract, Sections 5 to 9). Hashing is in `assertion-hash.ts`.
 *
 * Internal: the public surface is `verify` in `assertions.ts`. This module
 * imports only types from there, so the two do not form a runtime import
 * cycle.
 */
import { base64 } from '../../src/encodings/index.js';
import {
  assertionId,
  fail,
  hashAssertion,
  hasOwn,
  isJsonObject,
  type JsonObject,
} from './assertion-hash.js';
import type { AssertionKeyAlg, AssertionVerificationKeys } from './assertions.js';
import { unwrapKey, unwrapSymmetricKey } from './crypto/core/keys.js';
import {
  type CryptoService,
  isRsaKeyAlgorithm,
  type PublicKey,
  type SymmetricKey,
} from './crypto/declarations.js';
import {
  certificateSpki,
  decodeBase64Padded,
  decodeBase64urlStrict,
  jwkIdentity,
  MalformedKeyError,
  pemIdentity,
  spkiIdentity,
} from './key-identity.js';
import { scanStrictJson } from './strict-json.js';

const ASSERTION_ALGORITHMS: readonly string[] = [
  'RS256',
  'ES256',
  'HS256',
] satisfies readonly AssertionKeyAlg[];

function isBranded<B extends string>(value: unknown, brand: B): value is { _brand: B } {
  return isJsonObject(value) && value._brand === brand;
}

/** A short, quoted rendering of an untrusted value for error messages. */
function quoted(value: unknown): string {
  if (typeof value !== 'string') {
    return typeof value;
  }
  return JSON.stringify(value.length > 32 ? `${value.slice(0, 32)}...` : value);
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ---------------------------------------------------------------------------
// Section 6.1: key selection

function isUnset(value: unknown): boolean {
  return value === undefined || value === null || value === '';
}

/**
 * Pick the verification material for one assertion: the per-ID entry, else
 * the default key, else the payload key with HS256. Exactly one source is
 * chosen; the entry is returned as configured and validated by
 * {@link prepareVerificationKey}, so an invalid entry is an error rather than
 * a reason to fall through.
 */
export function selectVerificationKey(
  id: string,
  verificationKeys: AssertionVerificationKeys | undefined,
  payloadKey: SymmetricKey
): unknown {
  if (verificationKeys !== undefined && verificationKeys !== null) {
    if (!isJsonObject(verificationKeys)) {
      fail('configuration-error', 'assertion verification keys must be an object', id);
    }
    const keys: unknown = hasOwn(verificationKeys, 'Keys') ? verificationKeys.Keys : undefined;
    if (keys !== undefined && keys !== null) {
      if (typeof keys !== 'object') {
        fail('configuration-error', 'assertion verification Keys must be an object', id);
      }
      if (hasOwn(keys, id)) {
        return (keys as Record<string, unknown>)[id];
      }
    }
    const defaultKey: unknown = hasOwn(verificationKeys, 'DefaultKey')
      ? verificationKeys.DefaultKey
      : undefined;
    const absent =
      defaultKey === undefined ||
      defaultKey === null ||
      (isJsonObject(defaultKey) && isUnset(defaultKey.alg) && isUnset(defaultKey.key));
    if (!absent) {
      return defaultKey;
    }
  }
  return { alg: 'HS256', key: payloadKey };
}

/** Verification material checked against its configured algorithm. */
export type PreparedVerificationKey =
  | { alg: 'HS256'; secret: SymmetricKey }
  | {
      alg: 'RS256' | 'ES256';
      publicKey: PublicKey;
      /** The key's thumbprint, when it was configured as PEM. */
      identity?: string;
    };

const PEM_MARKER = new TextEncoder().encode('-----BEGIN');

function containsPem(bytes: Uint8Array): boolean {
  outer: for (let i = 0; i + PEM_MARKER.length <= bytes.length; i++) {
    for (let j = 0; j < PEM_MARKER.length; j++) {
      if (bytes[i + j] !== PEM_MARKER[j]) {
        continue outer;
      }
    }
    return true;
  }
  return false;
}

/** The raw bytes of a SymmetricKey from the default CryptoService, if it is one. */
function symmetricKeyBytes(key: SymmetricKey): Uint8Array | undefined {
  try {
    return unwrapSymmetricKey(key);
  } catch {
    return undefined;
  }
}

/**
 * Why a WebCrypto-backed public key cannot verify `alg`, if it cannot. Keys
 * from other CryptoService implementations are left to that implementation.
 */
function cryptoKeyProblem(publicKey: PublicKey, alg: 'RS256' | 'ES256'): string | undefined {
  let key: CryptoKey;
  try {
    key = unwrapKey(publicKey);
  } catch {
    return undefined;
  }
  if (key.type !== 'public' || !key.usages.includes('verify')) {
    return 'configured key is not a public key usable to verify';
  }
  const algorithm = key.algorithm as Partial<RsaHashedKeyAlgorithm & EcKeyAlgorithm>;
  const fits =
    alg === 'RS256'
      ? algorithm.name === 'RSASSA-PKCS1-v1_5' && algorithm.hash?.name === 'SHA-256'
      : algorithm.name === 'ECDSA' && algorithm.namedCurve === 'P-256';
  return fits ? undefined : `configured key is a ${String(algorithm.name)} key, not for ${alg}`;
}

/**
 * Check that a selected entry names a supported algorithm and holds usable key
 * material of the right type for it. Anything else is `configuration-error`.
 */
export async function prepareVerificationKey(
  entry: unknown,
  cryptoService: CryptoService,
  id?: string
): Promise<PreparedVerificationKey> {
  const configError = (detail: string, cause?: unknown): never =>
    fail('configuration-error', detail, id, cause);
  if (!isJsonObject(entry)) {
    return configError('verification key must be an object with alg and key');
  }
  const { alg, key } = entry;
  if (alg !== 'HS256' && alg !== 'RS256' && alg !== 'ES256') {
    return configError(`unsupported verification key algorithm ${quoted(alg)}`);
  }
  if (alg === 'HS256') {
    let secret: SymmetricKey;
    if (key instanceof Uint8Array) {
      if (!key.length) {
        return configError('HS256 verification key is empty');
      }
      try {
        secret = await cryptoService.importSymmetricKey(key);
      } catch (e) {
        return configError('HS256 verification key could not be imported', e);
      }
    } else if (isBranded(key, 'SymmetricKey')) {
      secret = key as SymmetricKey;
    } else if (isBranded(key, 'PrivateKey')) {
      return configError('cannot verify with a PrivateKey');
    } else {
      return configError('HS256 verification key must be bytes or a SymmetricKey');
    }
    // Public-key text is not a secret (spec Section 7).
    const bytes = key instanceof Uint8Array ? key : symmetricKeyBytes(secret);
    if (bytes && containsPem(bytes)) {
      return configError('HS256 verification key is PEM text, not a shared secret');
    }
    return { alg, secret };
  }
  let publicKey: PublicKey;
  let identity: string | undefined;
  if (typeof key === 'string') {
    if (!key.trim()) {
      return configError(`${alg} verification key is empty`);
    }
    try {
      publicKey = await cryptoService.importPublicKey(key, { usage: 'sign' });
    } catch (e) {
      return configError(`${alg} verification key could not be parsed`, e);
    }
    // Known now, so comparing an embedded key never needs to export this one.
    try {
      identity = await pemIdentity(key, cryptoService);
    } catch (e) {
      return configError(`${alg} verification key could not be read`, e);
    }
  } else if (isBranded(key, 'PublicKey')) {
    publicKey = key as PublicKey;
  } else if (isBranded(key, 'PrivateKey')) {
    return configError('cannot verify with a PrivateKey');
  } else {
    return configError(`${alg} verification key must be a PEM string or a PublicKey`);
  }
  const fits =
    alg === 'RS256'
      ? isRsaKeyAlgorithm(publicKey.algorithm)
      : publicKey.algorithm === 'ec:secp256r1';
  if (!fits) {
    return configError(`${alg} verification key is a ${publicKey.algorithm} key`);
  }
  const problem = cryptoKeyProblem(publicKey, alg);
  if (problem) {
    return configError(problem);
  }
  return identity === undefined ? { alg, publicKey } : { alg, publicKey, identity };
}

// ---------------------------------------------------------------------------
// Section 5.1: binding forms

/**
 * Determine the binding form (spec Section 5.1) and return the compact JWS of
 * a JWS binding. Fails `invalid-binding` or `unsupported-binding` otherwise.
 */
export function bindingJws(a: JsonObject, id?: string): string {
  if (!hasOwn(a, 'binding')) {
    fail('invalid-binding', 'assertion has no binding', id);
  }
  const binding = a.binding;
  if (!isJsonObject(binding)) {
    return fail('invalid-binding', 'binding is not a JSON object', id);
  }
  const hasSignature = hasOwn(binding, 'signature');
  const hasBdo = hasOwn(binding, 'bdo');
  if (hasSignature === hasBdo) {
    fail(
      'invalid-binding',
      hasSignature ? 'binding has both signature and bdo' : 'binding has neither signature nor bdo',
      id
    );
  }
  if (hasBdo) {
    fail('unsupported-binding', 'STANAG 4778 binding objects are not supported', id);
  }
  const { method, signature } = binding;
  if (typeof signature !== 'string') {
    fail('invalid-binding', 'binding signature is not a string', id);
  }
  if (hasOwn(binding, 'method')) {
    if (typeof method !== 'string') {
      fail('invalid-binding', 'binding method is not a string', id);
    }
    if (method !== 'jws' && method !== 'JWS') {
      fail('unsupported-binding', `unsupported binding method ${quoted(method)}`, id);
    }
  }
  return signature;
}

// ---------------------------------------------------------------------------
// Section 5.5: the binding JWS

function decodeJsonObjectPart(part: string, what: string, id?: string): JsonObject {
  const bytes = decodeBase64urlStrict(part);
  if (!bytes) {
    return fail('invalid-binding', `JWS ${what} is not base64url`, id);
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (e) {
    return fail('invalid-binding', `JWS ${what} is not UTF-8`, id, e);
  }
  // Duplicate header members would let readers disagree about alg or keys.
  const scan = scanStrictJson(text, 'json');
  if (!scan.ok) {
    return fail(
      'invalid-binding',
      `JWS ${what} is not JSON: ${scan.syntaxError ?? scan.failure.detail}`,
      id
    );
  }
  const parsed = JSON.parse(text) as unknown;
  if (!isJsonObject(parsed)) {
    return fail('invalid-binding', `JWS ${what} is not a JSON object`, id);
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Section 6.2: embedded keys

/**
 * The identity of the leaf of an embedded `x5c`. Every entry must be padded
 * standard base64; only the leaf is parsed, and no chain is built or
 * validated.
 */
async function x5cIdentity(x5c: unknown, cryptoService: CryptoService): Promise<string> {
  if (!Array.isArray(x5c) || !x5c.length) {
    throw new MalformedKeyError('x5c is not a nonempty array');
  }
  const certificates = x5c.map((entry: unknown) =>
    typeof entry === 'string' ? decodeBase64Padded(entry) : undefined
  );
  if (certificates.some((der) => der === undefined)) {
    throw new MalformedKeyError('x5c has an entry that is not a base64 string');
  }
  return spkiIdentity(certificateSpki(certificates[0]!), cryptoService);
}

/**
 * Spec Section 6.2. Embedded `jwk` and `x5c` headers never supply the
 * verification key; they may only name the key that was selected.
 */
async function checkEmbeddedKeys(
  header: JsonObject,
  key: PreparedVerificationKey,
  cryptoService: CryptoService,
  id?: string
): Promise<void> {
  const hasJwk = hasOwn(header, 'jwk');
  const hasX5c = hasOwn(header, 'x5c');
  if (!hasJwk && !hasX5c) {
    return;
  }
  if (key.alg === 'HS256') {
    fail('invalid-embedded-key', 'embedded keys are not allowed with an HMAC binding', id);
  }
  const embedded = async (what: string, identify: () => Promise<string>) => {
    try {
      return await identify();
    } catch (e) {
      return fail('invalid-embedded-key', `${what}: ${(e as Error).message}`, id, e);
    }
  };
  const jwk = hasJwk
    ? await embedded('jwk', () => jwkIdentity(header.jwk, cryptoService))
    : undefined;
  const leaf = hasX5c
    ? await embedded('x5c', () => x5cIdentity(header.x5c, cryptoService))
    : undefined;
  if (jwk !== undefined && leaf !== undefined && jwk !== leaf) {
    fail('invalid-embedded-key', 'jwk and x5c name different keys', id);
  }
  let selected = key.identity;
  if (selected === undefined) {
    try {
      const pem = await cryptoService.exportPublicKeyPem(key.publicKey);
      selected = await pemIdentity(pem, cryptoService);
    } catch (e) {
      return fail(
        'configuration-error',
        'configured key is not extractable, so an embedded jwk/x5c cannot be compared',
        id,
        e
      );
    }
  }
  if ((jwk ?? leaf) !== selected) {
    fail('signer-not-permitted', 'embedded key does not match the selected verification key', id);
  }
}

// ---------------------------------------------------------------------------
// Section 8: reader procedure, steps 3.3 to 3.9

/**
 * Verify one assertion's binding with already selected, prepared material.
 * `aggregateHash` is the decoded concatenation of the segment hashes;
 * `isLegacyTDF` selects hex-text instead of raw bytes for the assertion hash
 * inside `assertionSig`.
 */
export async function verifyAssertionBinding(
  a: JsonObject,
  aggregateHash: Uint8Array,
  key: PreparedVerificationKey,
  isLegacyTDF: boolean,
  cryptoService: CryptoService,
  id?: string
): Promise<void> {
  // 3.3 Binding form.
  const jws = bindingJws(a, id);

  // 3.4 JWS structure and header.
  const parts = jws.split('.');
  if (parts.length !== 3) {
    fail('invalid-binding', 'binding is not a compact JWS with three parts', id);
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  const header = decodeJsonObjectPart(headerPart, 'header', id);
  const payload = decodeJsonObjectPart(payloadPart, 'payload', id);
  if (hasOwn(header, 'crit')) {
    fail('invalid-binding', 'JWS crit header is not supported', id);
  }
  const { alg } = header;
  if (!hasOwn(header, 'alg') || typeof alg !== 'string') {
    return fail('unsupported-algorithm', 'JWS alg header is missing', id);
  }
  if (!ASSERTION_ALGORITHMS.includes(alg)) {
    fail('unsupported-algorithm', `JWS alg ${quoted(alg)} is not supported`, id);
  }
  if (alg !== key.alg) {
    fail('algorithm-mismatch', `JWS alg ${alg} does not match the selected key's ${key.alg}`, id);
  }

  // 3.5 Embedded keys.
  await checkEmbeddedKeys(header, key, cryptoService, id);

  // 3.6 Signature, with the selected key and its configured algorithm.
  const signingInput = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  const signature = decodeBase64urlStrict(signaturePart);
  let valid = false;
  if (signature) {
    try {
      valid =
        key.alg === 'HS256'
          ? await cryptoService.verifyHmac(signingInput, signature, key.secret)
          : await cryptoService.verify(signingInput, signature, key.publicKey, key.alg);
    } catch (e) {
      // A bad signature verifies as false; an exception means the key or the
      // CryptoService cannot do this verification at all.
      fail('configuration-error', 'the selected key cannot verify the binding', id, e);
    }
  }
  if (!valid) {
    fail('signature-invalid', 'binding signature does not verify with the selected key', id);
  }

  // 3.7 Claims.
  const { assertionHash, assertionSig } = payload;
  if (
    !hasOwn(payload, 'assertionHash') ||
    typeof assertionHash !== 'string' ||
    !hasOwn(payload, 'assertionSig') ||
    typeof assertionSig !== 'string'
  ) {
    fail('binding-mismatch', 'binding claims assertionHash and assertionSig must be strings', id);
  }

  // 3.8 Hash of the assertion as received.
  const computed = await hashAssertion(a, id, cryptoService);
  if (assertionHash !== computed.hex) {
    fail('binding-mismatch', 'assertionHash does not match the assertion', id);
  }

  // 3.9 assertionSig, in the one encoding the manifest version selects.
  const assertionHashBytes = isLegacyTDF ? new TextEncoder().encode(computed.hex) : computed.bytes;
  const expectedSig = base64.encodeArrayBuffer(concatBytes(aggregateHash, assertionHashBytes));
  if (assertionSig !== expectedSig) {
    fail('binding-mismatch', 'assertionSig does not match the segment hashes', id);
  }
}

/**
 * Verify one assertion read from a manifest: exact id, key selection,
 * configured-key validation, then {@link verifyAssertionBinding}.
 */
export async function verifyManifestAssertion(
  a: unknown,
  aggregateHash: Uint8Array,
  verificationKeys: AssertionVerificationKeys | undefined,
  payloadKey: SymmetricKey,
  isLegacyTDF: boolean,
  cryptoService: CryptoService
): Promise<void> {
  const id = assertionId(a);
  const entry = selectVerificationKey(id, verificationKeys, payloadKey);
  const key = await prepareVerificationKey(entry, cryptoService, id);
  await verifyAssertionBinding(a as JsonObject, aggregateHash, key, isLegacyTDF, cryptoService, id);
}
