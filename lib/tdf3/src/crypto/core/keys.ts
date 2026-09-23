import {
  ecAlgorithmToCurve,
  isEcKeyAlgorithm,
  isRsaKeyAlgorithm,
  type KeyAlgorithm,
  type PrivateKey,
  type PublicKey,
  rsaAlgorithmToModulusBits,
  type SymmetricKey,
} from '../declarations.js';

type InternalValue<T> = { readonly _internal: T };
type InternalCryptoKey = InternalValue<CryptoKey>;
type InternalBytes = InternalValue<Uint8Array>;

function readInternal(key: object): unknown {
  return (key as InternalValue<unknown>)._internal;
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return typeof value === 'object' && value !== null && 'type' in value && 'algorithm' in value;
}

function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

function unwrapBytes(key: object): Uint8Array {
  const internal = readInternal(key);
  if (!isBytes(internal)) throw new TypeError('Key is not owned by this crypto service');
  return internal;
}

/**
 * Wrap a CryptoKey as an opaque PublicKey.
 * @internal
 */
export function wrapPublicKey(key: CryptoKey, algorithm: KeyAlgorithm): PublicKey {
  const result = {
    _brand: 'PublicKey',
    algorithm,
    ...(isRsaKeyAlgorithm(algorithm) && { modulusBits: rsaAlgorithmToModulusBits(algorithm) }),
    ...(isEcKeyAlgorithm(algorithm) && { curve: ecAlgorithmToCurve(algorithm) }),
    _internal: key,
  } as PublicKey & InternalCryptoKey;
  return result;
}

/**
 * Wrap a CryptoKey as an opaque PrivateKey.
 * @internal
 */
export function wrapPrivateKey(key: CryptoKey, algorithm: KeyAlgorithm): PrivateKey {
  const result = {
    _brand: 'PrivateKey',
    algorithm,
    ...(isRsaKeyAlgorithm(algorithm) && { modulusBits: rsaAlgorithmToModulusBits(algorithm) }),
    ...(isEcKeyAlgorithm(algorithm) && { curve: ecAlgorithmToCurve(algorithm) }),
    _internal: key,
  } as PrivateKey & InternalCryptoKey;
  return result;
}

/**
 * Unwrap an opaque key to get the internal CryptoKey.
 * @internal
 */
export function unwrapKey(key: PublicKey | PrivateKey): CryptoKey {
  if (typeof key !== 'object' || key === null) {
    throw new TypeError('Key is not owned by this crypto service');
  }
  const internal = readInternal(key);
  if (!isCryptoKey(internal)) throw new TypeError('Key is not owned by this crypto service');
  return internal;
}

/**
 * Wrap raw key bytes as an opaque SymmetricKey.
 * @internal
 */
export function wrapSymmetricKey(keyBytes: Uint8Array): SymmetricKey {
  const result = {
    _brand: 'SymmetricKey',
    length: keyBytes.length * 8, // bits
    _internal: keyBytes,
  } as SymmetricKey & InternalBytes;
  return result;
}

/**
 * Unwrap an opaque SymmetricKey to get raw bytes.
 * @internal
 */
export function unwrapSymmetricKey(key: SymmetricKey): Uint8Array {
  if (typeof key !== 'object' || key === null) {
    throw new TypeError('Key is not owned by this crypto service');
  }
  return unwrapBytes(key);
}

/**
 * Wrap raw ML-KEM encapsulation key bytes as an opaque PublicKey.
 * @internal
 */
export function wrapMlKemPublicKey(bytes: Uint8Array, level: 768 | 1024): PublicKey {
  const result = {
    _brand: 'PublicKey',
    algorithm: `mlkem:${level}` as KeyAlgorithm,
    mlKemLevel: level,
    _internal: bytes,
  } as PublicKey & InternalBytes;
  return result;
}

/**
 * Wrap raw ML-KEM decapsulation key bytes as an opaque PrivateKey.
 * @internal
 */
export function wrapMlKemPrivateKey(bytes: Uint8Array, level: 768 | 1024): PrivateKey {
  const result = {
    _brand: 'PrivateKey',
    algorithm: `mlkem:${level}` as KeyAlgorithm,
    mlKemLevel: level,
    _internal: bytes,
  } as PrivateKey & InternalBytes;
  return result;
}

/**
 * Unwrap an opaque ML-KEM PublicKey or PrivateKey to get raw bytes.
 * @internal
 */
export function unwrapMlKemKey(key: PublicKey | PrivateKey): Uint8Array {
  if (typeof key !== 'object' || key === null) {
    throw new TypeError('Key is not owned by this crypto service');
  }
  const bytes = unwrapBytes(key);
  return bytes;
}
