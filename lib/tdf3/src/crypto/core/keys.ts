import {
  type KeyAlgorithm,
  type PrivateKey,
  type PublicKey,
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
  if (algorithm.startsWith('rsa:')) {
    result.modulusBits = parseInt(algorithm.split(':')[1], 10);
  } else if (algorithm.startsWith('ec:')) {
    const curvePart = algorithm.split(':')[1];
    result.curve =
      curvePart === 'secp256r1'
        ? 'P-256'
        : curvePart === 'secp384r1'
          ? 'P-384'
          : curvePart === 'secp521r1'
            ? 'P-521'
            : undefined;
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
  if (algorithm.startsWith('rsa:')) {
    result.modulusBits = parseInt(algorithm.split(':')[1], 10);
  } else if (algorithm.startsWith('ec:')) {
    const curvePart = algorithm.split(':')[1];
    result.curve =
      curvePart === 'secp256r1'
        ? 'P-256'
        : curvePart === 'secp384r1'
          ? 'P-384'
          : curvePart === 'secp521r1'
            ? 'P-521'
            : undefined;
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
