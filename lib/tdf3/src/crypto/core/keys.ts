import {
  type KeyAlgorithm,
  type MlKemAlgorithm,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';

function isMlKemAlgorithm(algorithm: string): algorithm is MlKemAlgorithm {
  return algorithm === 'mlkem:512' || algorithm === 'mlkem:768' || algorithm === 'mlkem:1024';
}

function mlKemLevelFromAlgorithm(algorithm: MlKemAlgorithm) {
  return Number.parseInt(algorithm.split(':')[1], 10) as 512 | 768 | 1024;
}

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
 * Wrap raw ML-KEM public key bytes as an opaque PublicKey.
 * @internal
 */
export function wrapMlKemPublicKey(key: Uint8Array, algorithm: MlKemAlgorithm): PublicKey {
  return {
    _brand: 'PublicKey',
    algorithm,
    mlKemLevel: mlKemLevelFromAlgorithm(algorithm),
    _internal: new Uint8Array(key),
  } as PublicKey;
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
 * Wrap raw ML-KEM private key bytes as an opaque PrivateKey.
 * @internal
 */
export function wrapMlKemPrivateKey(key: Uint8Array, algorithm: MlKemAlgorithm): PrivateKey {
  return {
    _brand: 'PrivateKey',
    algorithm,
    mlKemLevel: mlKemLevelFromAlgorithm(algorithm),
    _internal: new Uint8Array(key),
  } as PrivateKey;
}

/**
 * Unwrap an opaque key to get the internal CryptoKey.
 * @internal
 */
export function unwrapKey(key: PublicKey | PrivateKey): CryptoKey {
  if (isMlKemAlgorithm(key.algorithm)) {
    throw new ConfigurationError(`Key algorithm ${key.algorithm} is not a WebCrypto CryptoKey`);
  }
  return (key as any)._internal;
}

/**
 * Unwrap an ML-KEM public key to raw bytes.
 * @internal
 */
export function unwrapMlKemPublicKey(key: PublicKey): Uint8Array {
  if (!isMlKemAlgorithm(key.algorithm)) {
    throw new ConfigurationError(`Key algorithm ${key.algorithm} is not an ML-KEM public key`);
  }
  return (key as any)._internal;
}

/**
 * Unwrap an ML-KEM private key to raw bytes.
 * @internal
 */
export function unwrapMlKemPrivateKey(key: PrivateKey): Uint8Array {
  if (!isMlKemAlgorithm(key.algorithm)) {
    throw new ConfigurationError(`Key algorithm ${key.algorithm} is not an ML-KEM private key`);
  }
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
