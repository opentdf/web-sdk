import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import {
  type HkdfParams,
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
  unwrapSymmetricKey,
} from './keys.js';

const MLKEM = {
  512: ml_kem512,
  768: ml_kem768,
  1024: ml_kem1024,
} as const;

/** Ciphertext byte lengths per ML-KEM level (FIPS 203 Table 3). */
export const MLKEM_CT_SIZES: Record<512 | 768 | 1024, number> = {
  512: 768,
  768: 1088,
  1024: 1568,
};

function assertMlKemLevel(key: PublicKey | PrivateKey): 512 | 768 | 1024 {
  const level = key.mlKemLevel;
  if (level !== 512 && level !== 768 && level !== 1024) {
    throw new ConfigurationError(`ML-KEM key is missing a valid mlKemLevel (got ${level})`);
  }
  return level;
}

export async function generateMlKemKeyPair(level: 512 | 768 | 1024): Promise<KeyPair> {
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

/**
 * Derive a 256-bit AES-GCM key from raw input key material via HKDF.
 * Used to convert an ML-KEM shared secret into a usable AES key.
 */
export async function hkdfDerive(ikm: SymmetricKey, params: HkdfParams): Promise<SymmetricKey> {
  const ikmBytes = unwrapSymmetricKey(ikm);

  const hkdfKey = await crypto.subtle.importKey('raw', ikmBytes, 'HKDF', false, ['deriveKey']);

  const keyLength = params.keyLength ?? 256;
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: params.hash,
      salt: params.salt,
      info: params.info ?? new Uint8Array(0),
    },
    hkdfKey,
    { name: 'AES-GCM', length: keyLength },
    true,
    ['encrypt', 'decrypt']
  );

  const keyBytes = await crypto.subtle.exportKey('raw', derivedKey);
  return wrapSymmetricKey(new Uint8Array(keyBytes));
}
