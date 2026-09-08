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
 * ECDSA signatures come back as raw IEEE P1363 (`R || S`) — the fixed-width
 * encoding WebCrypto emits and the one RFC 7518 section 3.4 requires on the JWS
 * wire — so nothing transcodes between here and the token. RSA signatures have
 * a single encoding.
 */
export async function sign(
  data: Uint8Array,
  privateKey: PrivateKey,
  algorithm: AsymmetricSigningAlgorithm
): Promise<Uint8Array> {
  const { signParams } = getSigningAlgorithmParams(algorithm);

  // Unwrap the internal CryptoKey
  const key = unwrapKey(privateKey);

  return new Uint8Array(await crypto.subtle.sign(signParams, key, data));
}

/**
 * Verify signature with an asymmetric public key.
 *
 * Expects the encoding {@link sign} produces: raw IEEE P1363 for ECDSA. A
 * wrong-length signature fails verification rather than throwing.
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

  return crypto.subtle.verify(signParams, key, signature, data);
}
