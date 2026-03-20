import {
  type ECCurve,
  type HkdfParams,
  type KeyAlgorithm,
  type KeyPair,
  type PrivateKey,
  type PublicKey,
  type SymmetricKey,
} from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';
import { unwrapKey, wrapPrivateKey, wrapPublicKey, wrapSymmetricKey } from './keys.js';

/**
 * Map ECCurve to Web Crypto named curve.
 */
function curveToNamedCurve(curve: ECCurve): string {
  switch (curve) {
    case 'P-256':
      return 'P-256';
    case 'P-384':
      return 'P-384';
    case 'P-521':
      return 'P-521';
    default:
      throw new ConfigurationError(`Unsupported curve: ${curve}`);
  }
}

/**
 * Generate an EC key pair for ECDH key agreement.
 */
export async function generateECKeyPair(curve: ECCurve = 'P-256'): Promise<KeyPair> {
  const namedCurve = curveToNamedCurve(curve);

  const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve }, true, [
    'deriveBits',
  ]);

  let algorithm: KeyAlgorithm;
  switch (namedCurve) {
    case 'P-256':
      algorithm = 'ec:secp256r1';
      break;
    case 'P-384':
      algorithm = 'ec:secp384r1';
      break;
    case 'P-521':
      algorithm = 'ec:secp521r1';
      break;
    default:
      throw new ConfigurationError(`Unsupported curve: ${namedCurve}`);
  }

  return {
    publicKey: wrapPublicKey(keyPair.publicKey, algorithm),
    privateKey: wrapPrivateKey(keyPair.privateKey, algorithm),
  };
}

/**
 * Perform ECDH key agreement followed by HKDF key derivation.
 * Returns opaque symmetric key for symmetric encryption.
 */
export async function deriveKeyFromECDH(
  privateKey: PrivateKey,
  publicKey: PublicKey,
  hkdfParams: HkdfParams
): Promise<SymmetricKey> {
  const privateKeyCrypto = unwrapKey(privateKey);
  const publicKeyCrypto = unwrapKey(publicKey);

  const curve = publicKey.curve;
  if (!curve) {
    throw new ConfigurationError('EC curve not found on public key');
  }

  const curveBits: Record<ECCurve, number> = {
    'P-256': 256,
    'P-384': 384,
    'P-521': 528,
  };
  const bits = curveBits[curve];

  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKeyCrypto },
    privateKeyCrypto,
    bits
  );

  const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);

  const keyLength = hkdfParams.keyLength ?? 256;
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: hkdfParams.hash,
      salt: hkdfParams.salt,
      info: hkdfParams.info ?? new Uint8Array(0),
    },
    hkdfKey,
    { name: 'AES-GCM', length: keyLength },
    true,
    ['encrypt', 'decrypt']
  );

  const keyBytes = await crypto.subtle.exportKey('raw', derivedKey);
  return wrapSymmetricKey(new Uint8Array(keyBytes));
}
