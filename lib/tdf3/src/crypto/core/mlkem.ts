import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import {
  type KeyAlgorithm,
  type KeyPair,
  type MlKemAlgorithm,
  type MlKemLevel,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';
import {
  unwrapMlKemPrivateKey,
  unwrapMlKemPublicKey,
  wrapMlKemPrivateKey,
  wrapMlKemPublicKey,
  wrapSymmetricKey,
} from './keys.js';

type MlKemImplementation = {
  keygen: (seed?: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate: (publicKey: Uint8Array) => { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

export const ML_KEM_PUBLIC_KEY_LENGTHS: Record<MlKemLevel, number> = {
  512: 800,
  768: 1184,
  1024: 1568,
};

export const ML_KEM_PRIVATE_KEY_LENGTHS: Record<MlKemLevel, number> = {
  512: 1632,
  768: 2400,
  1024: 3168,
};

export const ML_KEM_CIPHERTEXT_LENGTHS: Record<MlKemLevel, number> = {
  512: 768,
  768: 1088,
  1024: 1568,
};

const ML_KEM_IMPLEMENTATIONS: Record<MlKemLevel, MlKemImplementation> = {
  512: ml_kem512,
  768: ml_kem768,
  1024: ml_kem1024,
};

let cachedZtdfSalt: Uint8Array | undefined;

export function isMlKemAlgorithm(algorithm: string): algorithm is MlKemAlgorithm {
  return algorithm === 'mlkem:512' || algorithm === 'mlkem:768' || algorithm === 'mlkem:1024';
}

export function mlKemAlgorithmFromLevel(level: MlKemLevel): MlKemAlgorithm {
  if (!(level in ML_KEM_IMPLEMENTATIONS)) {
    throw new ConfigurationError(`Unsupported ML-KEM level: ${level}`);
  }
  return `mlkem:${level}` as MlKemAlgorithm;
}

export function mlKemLevelFromAlgorithm(algorithm: string): MlKemLevel | undefined {
  if (!isMlKemAlgorithm(algorithm)) {
    return undefined;
  }
  return Number.parseInt(algorithm.split(':')[1], 10) as MlKemLevel;
}

export function mlKemPublicKeyAlgorithmFromLength(length: number): MlKemAlgorithm | undefined {
  switch (length) {
    case ML_KEM_PUBLIC_KEY_LENGTHS[512]:
      return 'mlkem:512';
    case ML_KEM_PUBLIC_KEY_LENGTHS[768]:
      return 'mlkem:768';
    case ML_KEM_PUBLIC_KEY_LENGTHS[1024]:
      return 'mlkem:1024';
    default:
      return undefined;
  }
}

export function mlKemPrivateKeyAlgorithmFromLength(length: number): MlKemAlgorithm | undefined {
  switch (length) {
    case ML_KEM_PRIVATE_KEY_LENGTHS[512]:
      return 'mlkem:512';
    case ML_KEM_PRIVATE_KEY_LENGTHS[768]:
      return 'mlkem:768';
    case ML_KEM_PRIVATE_KEY_LENGTHS[1024]:
      return 'mlkem:1024';
    default:
      return undefined;
  }
}

export function mlKemCiphertextLengthForAlgorithm(algorithm: KeyAlgorithm): number {
  const level = mlKemLevelFromAlgorithm(algorithm);
  if (!level) {
    throw new ConfigurationError(`Unsupported ML-KEM algorithm: ${algorithm}`);
  }
  return ML_KEM_CIPHERTEXT_LENGTHS[level];
}

async function getZtdfSalt(): Promise<Uint8Array> {
  if (cachedZtdfSalt) {
    return cachedZtdfSalt;
  }
  cachedZtdfSalt = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode('TDF'))
  );
  return cachedZtdfSalt;
}

async function hkdfSharedSecret(sharedSecret: Uint8Array): Promise<SymmetricKey> {
  const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: await getZtdfSalt(),
      info: new Uint8Array(0),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const keyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', derivedKey));
  return wrapSymmetricKey(keyBytes);
}

function implementationForLevel(level: MlKemLevel): MlKemImplementation {
  const implementation = ML_KEM_IMPLEMENTATIONS[level];
  if (!implementation) {
    throw new ConfigurationError(`Unsupported ML-KEM level: ${level}`);
  }
  return implementation;
}

export async function generateMlKemKeyPair(level: MlKemLevel, seed?: Uint8Array): Promise<KeyPair> {
  const algorithm = mlKemAlgorithmFromLevel(level);
  const implementation = implementationForLevel(level);
  const { publicKey, secretKey } = implementation.keygen(seed);
  return {
    publicKey: wrapMlKemPublicKey(publicKey, algorithm),
    privateKey: wrapMlKemPrivateKey(secretKey, algorithm),
  };
}

export async function mlKemEncapsulate(
  publicKey: PublicKey
): Promise<{ ciphertext: Uint8Array; sharedSecret: SymmetricKey }> {
  const level = mlKemLevelFromAlgorithm(publicKey.algorithm);
  if (!level || publicKey.mlKemLevel !== level) {
    throw new ConfigurationError(`ML-KEM public key metadata mismatch: ${publicKey.algorithm}`);
  }
  const implementation = implementationForLevel(level);
  const { cipherText, sharedSecret } = implementation.encapsulate(unwrapMlKemPublicKey(publicKey));
  return {
    ciphertext: new Uint8Array(cipherText),
    sharedSecret: await hkdfSharedSecret(new Uint8Array(sharedSecret)),
  };
}

export async function mlKemDecapsulate(
  privateKey: PrivateKey,
  ciphertext: Uint8Array
): Promise<SymmetricKey> {
  const level = mlKemLevelFromAlgorithm(privateKey.algorithm);
  if (!level || privateKey.mlKemLevel !== level) {
    throw new ConfigurationError(`ML-KEM private key metadata mismatch: ${privateKey.algorithm}`);
  }
  if (ciphertext.byteLength !== ML_KEM_CIPHERTEXT_LENGTHS[level]) {
    throw new ConfigurationError(
      `ML-KEM ciphertext length ${ciphertext.byteLength} does not match ${privateKey.algorithm}`
    );
  }
  const implementation = implementationForLevel(level);
  const sharedSecret = implementation.decapsulate(
    new Uint8Array(ciphertext),
    unwrapMlKemPrivateKey(privateKey)
  );
  return hkdfSharedSecret(new Uint8Array(sharedSecret));
}
