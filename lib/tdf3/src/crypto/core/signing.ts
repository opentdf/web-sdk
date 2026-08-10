import {
  type AsymmetricSigningAlgorithm,
  type PrivateKey,
  type PublicKey,
} from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';
import { unwrapKey } from './keys.js';

/**
 * Get the Web Crypto algorithm parameters for a signing algorithm.
 */
function getSigningAlgorithmParams(algorithm: AsymmetricSigningAlgorithm): {
  importParams: RsaHashedImportParams | EcKeyImportParams;
  signParams: AlgorithmIdentifier | EcdsaParams;
} {
  switch (algorithm) {
    case 'RS256':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        signParams: 'RSASSA-PKCS1-v1_5',
      };
    case 'ES256':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-256' },
        signParams: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
      };
    case 'ES384':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-384' },
        signParams: { name: 'ECDSA', hash: 'SHA-384' } as EcdsaParams,
      };
    case 'ES512':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-521' },
        signParams: { name: 'ECDSA', hash: 'SHA-512' } as EcdsaParams,
      };
    default:
      throw new ConfigurationError(`Unsupported signing algorithm: ${algorithm}`);
  }
}

/**
 * Sign data with an asymmetric private key.
 *
 * ECDSA signatures come back in raw IEEE P1363 (R || S) form, which is what
 * WebCrypto produces and what JWS requires (RFC 7518 §3.4). RSA signatures are
 * raw bytes either way.
 */
export async function sign(
  data: Uint8Array,
  privateKey: PrivateKey,
  algorithm: AsymmetricSigningAlgorithm
): Promise<Uint8Array> {
  const { signParams } = getSigningAlgorithmParams(algorithm);

  // Unwrap the internal CryptoKey
  const key = unwrapKey(privateKey);

  // Sign the data
  const signature = await crypto.subtle.sign(signParams, key, data);

  return new Uint8Array(signature);
}

/**
 * Verify signature with an asymmetric public key.
 *
 * Expects the same raw encoding {@link sign} produces: IEEE P1363 (R || S) for
 * ECDSA, raw bytes for RSA.
 */
export async function verify(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: PublicKey,
  algorithm: AsymmetricSigningAlgorithm
): Promise<boolean> {
  const { signParams } = getSigningAlgorithmParams(algorithm);

  // Unwrap the internal CryptoKey
  const key = unwrapKey(publicKey);

  // Verify the signature
  return crypto.subtle.verify(signParams, key, signature, data);
}
