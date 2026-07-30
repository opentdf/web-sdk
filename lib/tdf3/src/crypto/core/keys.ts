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

/**
 * Wrap a CryptoKey as an opaque PublicKey.
 * @internal
 */
export function wrapPublicKey(key: CryptoKey, algorithm: KeyAlgorithm): PublicKey {
  const result: any = {
    _brand: 'PublicKey',
    algorithm,
    _internal: key,
  };
  if (isRsaKeyAlgorithm(algorithm)) {
    result.modulusBits = rsaAlgorithmToModulusBits(algorithm);
  } else if (isEcKeyAlgorithm(algorithm)) {
    result.curve = ecAlgorithmToCurve(algorithm);
  }
  return result as PublicKey;
}

/**
 * Wrap a CryptoKey as an opaque PrivateKey.
 * @internal
 */
export function wrapPrivateKey(key: CryptoKey, algorithm: KeyAlgorithm): PrivateKey {
  const result: any = {
    _brand: 'PrivateKey',
    algorithm,
    _internal: key,
  };
  if (isRsaKeyAlgorithm(algorithm)) {
    result.modulusBits = rsaAlgorithmToModulusBits(algorithm);
  } else if (isEcKeyAlgorithm(algorithm)) {
    result.curve = ecAlgorithmToCurve(algorithm);
  }
  return result as PrivateKey;
}

/**
 * Unwrap an opaque key to get the internal CryptoKey.
 * @internal
 */
export function unwrapKey(key: PublicKey | PrivateKey): CryptoKey {
  return (key as any)._internal;
}

/**
 * Wrap raw key bytes as an opaque SymmetricKey.
 * @internal
 */
export function wrapSymmetricKey(keyBytes: Uint8Array): SymmetricKey {
  return {
    _brand: 'SymmetricKey',
    length: keyBytes.length * 8, // bits
    _internal: keyBytes,
  } as SymmetricKey;
}

/**
 * Unwrap an opaque SymmetricKey to get raw bytes.
 * @internal
 */
export function unwrapSymmetricKey(key: SymmetricKey): Uint8Array {
  return (key as any)._internal;
}

/**
 * Wrap raw ML-KEM encapsulation key bytes as an opaque PublicKey.
 * @internal
 */
export function wrapMlKemPublicKey(bytes: Uint8Array, level: 768 | 1024): PublicKey {
  return {
    _brand: 'PublicKey',
    algorithm: `mlkem:${level}` as KeyAlgorithm,
    mlKemLevel: level,
    _internal: bytes,
  } as unknown as PublicKey;
}

/**
 * Wrap raw ML-KEM decapsulation key bytes as an opaque PrivateKey.
 * @internal
 */
export function wrapMlKemPrivateKey(bytes: Uint8Array, level: 768 | 1024): PrivateKey {
  return {
    _brand: 'PrivateKey',
    algorithm: `mlkem:${level}` as KeyAlgorithm,
    mlKemLevel: level,
    _internal: bytes,
  } as unknown as PrivateKey;
}

/**
 * Unwrap an opaque ML-KEM PublicKey or PrivateKey to get raw bytes.
 * @internal
 */
export function unwrapMlKemKey(key: PublicKey | PrivateKey): Uint8Array {
  return (key as any)._internal as Uint8Array;
}
