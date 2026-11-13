import { base64, hex } from '../../src/encodings/index.js';
import { asError, AssertionVerificationError, ConfigurationError } from '../../src/errors.js';
import { tdfSpecVersion, version as sdkVersion } from '../../src/version.js';
import {
  assertionDigest,
  assertionId,
  computeAssertionHash,
  prepareVerificationKey,
  verifyAssertionBinding,
} from './assertion-verifier.js';
import {
  type CryptoService,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from './crypto/declarations.js';
import { signJwt, type JwtHeader } from './crypto/jwt.js';

export { computeAssertionHash };

export type AssertionKeyAlg = 'ES256' | 'RS256' | 'HS256';
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
 * Computes the assertion hash: lowercase hex SHA-256 of the JCS (RFC 8785)
 * form of the assertion with only its top-level `binding` member removed.
 * Every other member is hashed, at any depth, including members this SDK does
 * not model.
 *
 * Pass the object exactly as parsed from the manifest. To hash raw JSON text
 * with the contract's strict parsing rules applied, use
 * {@link computeAssertionHash}.
 *
 * @param a - The assertion to hash, as a plain JSON object
 * @param cryptoService - The crypto service to use for hashing
 * @returns the hexadecimal string representation of the hash
 */
export async function hash(
  a: Assertion | Record<string, unknown>,
  cryptoService: CryptoService
): Promise<string> {
  const digest = await assertionDigest(a, cryptoService);
  return hex.encodeArrayBuffer(digest);
}

/**
 * Signs the assertion claims with the provided key.
 *
 * @param payload - The claims to sign.
 * @param key - The key used for signing.
 * @param cryptoService - The crypto service to use for signing.
 * @returns A promise that resolves to the compact JWS.
 */
async function sign(
  payload: AssertionPayload,
  key: AssertionKey,
  cryptoService: CryptoService
): Promise<string> {
  const header: JwtHeader = { alg: key.alg };

  if (typeof key.key === 'object' && '_brand' in key.key && key.key._brand === 'PublicKey') {
    throw new ConfigurationError(
      'Cannot sign assertion with PublicKey. Use PrivateKey or SymmetricKey for signing.'
    );
  }

  let signingMaterial: PrivateKey | SymmetricKey;
  if (typeof key.key === 'string') {
    if (!cryptoService.importPrivateKey) {
      throw new ConfigurationError(
        'CryptoService does not support importing private keys. Cannot sign assertion with a PEM string. Use PrivateKey or SymmetricKey for signing.'
      );
    }
    signingMaterial = await cryptoService.importPrivateKey(key.key, {
      usage: 'sign',
      extractable: false,
    });
  } else if (key.key instanceof Uint8Array) {
    signingMaterial = await cryptoService.importSymmetricKey(key.key);
  } else {
    signingMaterial = key.key;
  }

  try {
    return await signJwt(cryptoService, payload, signingMaterial, header);
  } catch (error) {
    throw new ConfigurationError(`Signing assertion failed: ${String(error)}`, asError(error));
  }
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
 * Verifies one assertion with the given, already selected key (ZTDF assertions
 * contract, Section 8 steps 3.1 and 3.3 to 3.9).
 *
 * The signature is checked only with `key` and its configured algorithm. A
 * `jwk` or `x5c` header in the binding never supplies the key: it must name
 * the same public key as `key`, and either one is rejected when `key` is
 * HS256.
 *
 * @param thiz - The assertion to verify, exactly as parsed from the manifest.
 * @param aggregateHash - The aggregate hash for integrity checking.
 * @param key - The key used for verification.
 * @param isLegacyTDF - Whether this is a legacy TDF format.
 * @param cryptoService - The crypto service to use for verification.
 * @throws {AssertionVerificationError} If verification fails; its `reason` says why.
 */
export async function verify(
  thiz: Assertion,
  aggregateHash: Uint8Array,
  key: AssertionKey,
  isLegacyTDF: boolean,
  cryptoService: CryptoService
): Promise<void> {
  const id = assertionId(thiz);
  const prepared = await prepareVerificationKey(key, cryptoService, id);
  await verifyAssertionBinding(thiz, aggregateHash, prepared, isLegacyTDF, cryptoService, id);
}

/**
 * Creates an Assertion object with the specified properties.
 *
 * @param aggregateHash - The aggregate hash for the assertion.
 * @param assertionConfig - The configuration for the assertion.
 * @param cryptoService - The crypto service to use for signing.
 * @param targetVersion - The target TDF spec version.
 * @returns The created assertion.
 */
export async function CreateAssertion(
  aggregateHash: Uint8Array | string,
  assertionConfig: AssertionConfig,
  cryptoService: CryptoService,
  targetVersion?: string
): Promise<Assertion> {
  if (!assertionConfig.signingKey) {
    throw new ConfigurationError('Assertion signing key is required');
  }
  const { id, type, scope, appliesToState, statement } = assertionConfig;
  if (typeof id !== 'string' || !id) {
    throw new ConfigurationError('Assertion id must be a nonempty string');
  }

  // The wire object: every member except binding, and nothing from the
  // configuration that is not part of the assertion (such as the signing key).
  // Hash its serialized form with the reader's rules, and write exactly that
  // object, so what readers hash is what was signed.
  const wireJson = JSON.stringify({
    id,
    type,
    scope,
    ...(appliesToState !== undefined && { appliesToState }),
    statement,
  });
  let assertionHash: string;
  try {
    assertionHash = await computeAssertionHash(wireJson, cryptoService);
  } catch (error) {
    // A writer-side error about the caller's input, not a tampered file.
    if (error instanceof AssertionVerificationError) {
      throw new ConfigurationError(
        `Cannot write an assertion that readers would reject (${error.reason}${
          error.detail ? `: ${error.detail}` : ''
        })`
      );
    }
    throw error;
  }
  const assertionHashBytes = new Uint8Array(hex.decodeArrayBuffer(assertionHash));

  let encodedHash: string;
  switch (targetVersion || '4.3.0') {
    case '4.2.2':
      if (typeof aggregateHash !== 'string') {
        throw new ConfigurationError('Aggregate hash must be a string for TDF spec version 4.2.2');
      }
      encodedHash = base64.encode(aggregateHash + assertionHash);
      break;
    case '4.3.0': {
      if (typeof aggregateHash === 'string') {
        throw new ConfigurationError(
          'Aggregate hash must be a typed array for TDF spec version 4.3.0'
        );
      }
      const combinedHash = concatenateUint8Arrays(aggregateHash, assertionHashBytes);
      encodedHash = base64.encodeArrayBuffer(combinedHash);
      break;
    }
    default:
      throw new ConfigurationError(`Unsupported TDF spec version: [${targetVersion}]`);
  }

  const signature = await sign(
    { assertionHash, assertionSig: encodedHash },
    assertionConfig.signingKey,
    cryptoService
  );
  const assertion = JSON.parse(wireJson) as Assertion;
  assertion.binding = { method: 'jws', signature };
  return assertion;
}

// TODO: Split AssertionKey into two separate types:
//   - AssertionSigningKey: key restricted to PrivateKey | SymmetricKey (no strings, no raw bytes)
//   - AssertionVerificationKey: key restricted to string | PublicKey | SymmetricKey
// This would make the signing/verification distinction type-safe rather than relying on runtime checks.
// AssertionConfig.signingKey would use AssertionSigningKey; verify() and AssertionVerificationKeys would use AssertionVerificationKey.

/**
 * Key used for signing or verifying assertions.
 * For asymmetric algorithms (RS256, ES256): PEM string, PrivateKey (for signing), or PublicKey (for verification).
 * For symmetric algorithms (HS256): Uint8Array or SymmetricKey (opaque).
 */
export type AssertionKey = {
  alg: AssertionKeyAlg;
  key: string | Uint8Array | PrivateKey | PublicKey | SymmetricKey;
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

/**
 * Verification keys for assertions. Each assertion is checked with exactly one
 * source, chosen by its exact `id`:
 *
 * 1. `Keys[id]`, when that entry exists;
 * 2. otherwise `DefaultKey`, when it is set;
 * 3. otherwise the payload key, with HS256.
 *
 * A failure with the chosen source is final; no other source is tried. An
 * entry that is chosen but empty or invalid fails with `configuration-error`
 * instead of falling through. Keys embedded in a binding (`jwk`, `x5c`) never
 * add to these.
 */
export type AssertionVerificationKeys = {
  /**
   * Used for every assertion whose `id` has no entry in `Keys`. That includes
   * assertions the writer bound with the payload key, such as the
   * `system-metadata` assertion Java writers add, so files that carry one fail
   * verification when a default key is set. To verify such files, configure
   * per-ID keys instead.
   */
  DefaultKey?: AssertionKey;
  /** Keys for specific assertion ids. */
  Keys: Record<string, AssertionKey>;
};

/**
 * Metadata structure for system information.
 */
type SystemMetadata = {
  tdf_spec_version: string;
  creation_date: string;
  sdk_version: string;
  browser_user_agent?: string;
  // platform is often the same as os in browser, but kept for consistency with original Go struct
  platform?: string;
};

/**
 * Returns a default assertion configuration populated with system metadata.
 */
export function getSystemMetadataAssertionConfig(): AssertionConfig {
  let platformIdentifier = 'unknown';
  if (typeof navigator !== 'undefined') {
    if (typeof navigator.userAgent === 'string') {
      platformIdentifier = navigator.userAgent;
    } else if (typeof navigator.platform === 'string') {
      platformIdentifier = navigator.platform; // Deprecated, but used as a fallback
    }
  }

  const metadata: SystemMetadata = {
    tdf_spec_version: tdfSpecVersion,
    creation_date: new Date().toISOString(),
    sdk_version: `JS-${sdkVersion}`, // Prefixed to distinguish from Go SDK version
    browser_user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
    platform: platformIdentifier,
  };

  const metadataJSON = JSON.stringify(metadata);

  return {
    id: 'system-metadata', // Consistent ID for this type of assertion
    type: 'other', // General type for metadata assertions
    scope: 'tdo', // Metadata typically applies to the TDF Data Object as a whole
    appliesToState: 'unencrypted', // Metadata itself is not encrypted by this assertion's scope
    statement: {
      format: 'json',
      schema: 'system-metadata-v1', // A schema name for this metadata
      value: metadataJSON,
    },
  };
}

function concatenateUint8Arrays(array1: Uint8Array, array2: Uint8Array): Uint8Array {
  const combinedLength = array1.length + array2.length;
  const combinedArray = new Uint8Array(combinedLength);

  combinedArray.set(array1, 0);
  combinedArray.set(array2, array1.length);

  return combinedArray;
}
