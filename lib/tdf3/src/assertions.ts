import { canonicalizeEx } from 'json-canonicalize';
import { base64, hex } from '../../src/encodings/index.js';
import { ConfigurationError, IntegrityError, InvalidFileError } from '../../src/errors.js';
import { tdfSpecVersion, version as sdkVersion } from '../../src/version.js';
import {
  type CryptoService,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from './crypto/declarations.js';
import { decodeProtectedHeader, signJwt, verifyJwt, type JwtHeader } from './crypto/jwt.js';
import { extractPublicKeyPem, jwkToPublicKeyPem } from './crypto/index.js';

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
 * Computes the SHA-256 hash of the assertion object, excluding the 'binding' and 'hash' properties.
 *
 * @param a - The assertion to hash
 * @param cryptoService - The crypto service to use for hashing
 * @returns the hexadecimal string representation of the hash
 */
export async function hash(a: Assertion, cryptoService: CryptoService): Promise<string> {
  const result = canonicalizeEx(a, {
    exclude: ['binding', 'hash', 'sign', 'verify', 'signingKey'],
  });

  const hashBytes = await cryptoService.digest('SHA-256', new TextEncoder().encode(result));
  return hex.encodeArrayBuffer(hashBytes.buffer);
}

/**
 * Signs the given hash and signature using the provided key and sets the binding method and signature.
 *
 * @param thiz - The assertion to sign.
 * @param assertionHash - The hash to be signed.
 * @param sig - The signature to be signed.
 * @param key - The key used for signing.
 * @param cryptoService - The crypto service to use for signing.
 * @returns A promise that resolves to the signed assertion.
 */
async function sign(
  thiz: Assertion,
  assertionHash: string,
  sig: string,
  key: AssertionKey,
  cryptoService: CryptoService
): Promise<Assertion> {
  const payload: AssertionPayload = {
    assertionHash,
    assertionSig: sig,
  };

  const header: JwtHeader = { alg: key.alg };

  // Runtime check: ensure we have a signing key, not a verification key
  if (typeof key.key === 'string') {
    throw new ConfigurationError(
      'Cannot sign assertion with a PEM string. Use PrivateKey or SymmetricKey for signing.'
    );
  }
  if (key.key instanceof Uint8Array) {
    throw new ConfigurationError(
      'Cannot sign assertion with raw Uint8Array. Use SymmetricKey for signing.'
    );
  }
  if (typeof key.key === 'object' && '_brand' in key.key && key.key._brand === 'PublicKey') {
    throw new ConfigurationError(
      'Cannot sign assertion with PublicKey. Use PrivateKey or SymmetricKey for signing.'
    );
  }

  let token: string;
  try {
    token = await signJwt(cryptoService, payload, key.key as PrivateKey | SymmetricKey, header);
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
 * @param thiz - The assertion to verify.
 * @param aggregateHash - The aggregate hash for integrity checking.
 * @param key - The key used for verification.
 * @param isLegacyTDF - Whether this is a legacy TDF format.
 * @param cryptoService - The crypto service to use for verification.
 * @throws {InvalidFileError} If the verification fails.
 * @throws {IntegrityError} If the integrity check fails.
 */
export async function verify(
  thiz: Assertion,
  aggregateHash: Uint8Array,
  key: AssertionKey,
  isLegacyTDF: boolean,
  cryptoService: CryptoService
): Promise<void> {
  let payload: AssertionPayload;
  try {
    // Parse JWT header to check for embedded keys (jwk or x5c)
    const header = decodeProtectedHeader(thiz.binding.signature);

    // Runtime check: ensure we have a verification key, not a signing key
    if (typeof key.key === 'object' && '_brand' in key.key && key.key._brand === 'PrivateKey') {
      throw new ConfigurationError(
        'Cannot verify assertion with PrivateKey. Use PublicKey or SymmetricKey for verification.'
      );
    }
    let verificationKey: string | Uint8Array | PublicKey | SymmetricKey = key.key;

    if (header.jwk) {
      // Convert embedded JWK to PEM
      verificationKey = await jwkToPublicKeyPem(header.jwk as JsonWebKey);
    } else if (header.x5c && Array.isArray(header.x5c) && header.x5c.length > 0) {
      // Extract public key from X.509 certificate
      const cert = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
      verificationKey = await extractPublicKeyPem(cert);
    }

    const result = await verifyJwt(cryptoService, thiz.binding.signature, verificationKey, {
      algorithms: [key.alg],
    });
    payload = result.payload as AssertionPayload;
  } catch (error) {
    throw new InvalidFileError(`Verifying assertion failed: ${error.message}`, error);
  }
  const { assertionHash, assertionSig } = payload;

  // Get the hash of the assertion
  const hashOfAssertion = await hash(thiz, cryptoService);

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

  const a: Assertion = {
    id: assertionConfig.id,
    type: assertionConfig.type,
    scope: assertionConfig.scope,
    appliesToState: assertionConfig.appliesToState,
    statement: assertionConfig.statement,
    // empty binding
    binding: { method: '', signature: '' },
  };

  const assertionHash = await hash(a, cryptoService);
  let encodedHash: string;
  switch (targetVersion || '4.3.0') {
    case '4.2.2':
      if (typeof aggregateHash !== 'string') {
        throw new ConfigurationError('Aggregate hash must be a string for TDF spec version 4.2.2');
      }
      encodedHash = base64.encode(aggregateHash + assertionHash);
      break;
    case '4.3.0':
      if (typeof aggregateHash === 'string') {
        throw new ConfigurationError(
          'Aggregate hash must be a typed array for TDF spec version 4.3.0'
        );
      }
      const combinedHash = concatenateUint8Arrays(
        aggregateHash,
        new Uint8Array(hex.decodeArrayBuffer(assertionHash))
      );
      encodedHash = base64.encodeArrayBuffer(combinedHash);
      break;
    default:
      throw new ConfigurationError(`Unsupported TDF spec version: [${targetVersion}]`);
  }

  return await sign(a, assertionHash, encodedHash, assertionConfig.signingKey, cryptoService);
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

// AssertionVerificationKeys represents the verification keys for assertions.
export type AssertionVerificationKeys = {
  DefaultKey?: AssertionKey;
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
