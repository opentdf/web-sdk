import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import {
  type KeyPair,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';
import {
  unwrapMlKemKey,
  wrapMlKemPrivateKey,
  wrapMlKemPublicKey,
  wrapSymmetricKey,
} from './keys.js';

const MLKEM: Record<768 | 1024, typeof ml_kem768 | typeof ml_kem1024> = {
  768: ml_kem768,
  1024: ml_kem1024,
} as const;

/** Ciphertext byte lengths per ML-KEM level (FIPS 203 Table 3). */
export const MLKEM_CT_SIZES: Record<768 | 1024, number> = {
  768: 1088,
  1024: 1568,
};

function assertMlKemLevel(key: PublicKey | PrivateKey): 768 | 1024 {
  const level = key.mlKemLevel;
  if (level !== 768 && level !== 1024) {
    throw new ConfigurationError(`ML-KEM key is missing a valid mlKemLevel (got ${level})`);
  }
  return level;
}

export async function generateMlKemKeyPair(level: 768 | 1024): Promise<KeyPair> {
  const { publicKey, secretKey } = MLKEM[level].keygen();
  return {
    publicKey: wrapMlKemPublicKey(publicKey, level),
    privateKey: wrapMlKemPrivateKey(secretKey, level),
  };
}

export async function mlKemEncapsulate(
  pk: PublicKey
): Promise<{ ciphertext: Uint8Array; sharedSecret: SymmetricKey }> {
  const level = assertMlKemLevel(pk);
  const ekBytes = unwrapMlKemKey(pk);
  const { cipherText, sharedSecret } = MLKEM[level].encapsulate(ekBytes);
  return {
    ciphertext: cipherText,
    sharedSecret: wrapSymmetricKey(sharedSecret),
  };
}

export async function mlKemDecapsulate(sk: PrivateKey, ct: Uint8Array): Promise<SymmetricKey> {
  const level = assertMlKemLevel(sk);
  const dkBytes = unwrapMlKemKey(sk);
  const sharedSecret = MLKEM[level].decapsulate(ct, dkBytes);
  return wrapSymmetricKey(sharedSecret);
}
