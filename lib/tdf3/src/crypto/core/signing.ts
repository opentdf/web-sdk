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
 * Convert IEEE P1363 signature format (used by WebCrypto ECDSA) to DER format (used by JWT).
 * RS256 signatures don't need conversion.
 */
function ieeeP1363ToDer(signature: Uint8Array, algorithm: AsymmetricSigningAlgorithm): Uint8Array {
  if (algorithm === 'RS256') {
    return signature;
  }

  const halfLen = signature.length / 2;
  const r = signature.slice(0, halfLen);
  const s = signature.slice(halfLen);

  const trimLeadingZeros = (arr: Uint8Array): Uint8Array => {
    let index = 0;
    while (index < arr.length - 1 && arr[index] === 0) index++;
    return arr.slice(index);
  };

  let rTrimmed = trimLeadingZeros(r);
  let sTrimmed = trimLeadingZeros(s);

  if (rTrimmed[0] & 0x80) {
    const padded = new Uint8Array(rTrimmed.length + 1);
    padded.set(rTrimmed, 1);
    rTrimmed = padded;
  }
  if (sTrimmed[0] & 0x80) {
    const padded = new Uint8Array(sTrimmed.length + 1);
    padded.set(sTrimmed, 1);
    sTrimmed = padded;
  }

  const rDer = new Uint8Array([0x02, rTrimmed.length, ...rTrimmed]);
  const sDer = new Uint8Array([0x02, sTrimmed.length, ...sTrimmed]);

  const seqLen = rDer.length + sDer.length;
  const lenBytes = seqLen < 128 ? new Uint8Array([seqLen]) : new Uint8Array([0x81, seqLen]);
  const result = new Uint8Array(1 + lenBytes.length + seqLen);
  result[0] = 0x30;
  result.set(lenBytes, 1);
  result.set(rDer, 1 + lenBytes.length);
  result.set(sDer, 1 + lenBytes.length + rDer.length);

  return result;
}

/**
 * Convert DER signature format (used by JWT) to IEEE P1363 format (used by WebCrypto ECDSA).
 * RS256 signatures don't need conversion.
 */
function derToIeeeP1363(signature: Uint8Array, algorithm: AsymmetricSigningAlgorithm): Uint8Array {
  if (algorithm === 'RS256') {
    return signature;
  }

  let componentLen: number;
  switch (algorithm) {
    case 'ES256':
      componentLen = 32;
      break;
    case 'ES384':
      componentLen = 48;
      break;
    case 'ES512':
      componentLen = 66;
      break;
    default:
      throw new ConfigurationError(`Unsupported algorithm for DER conversion: ${algorithm}`);
  }

  if (signature[0] !== 0x30) {
    throw new ConfigurationError('Invalid DER signature: expected SEQUENCE');
  }

  let offset = 1;
  if (signature[offset] & 0x80) {
    const lenBytesCount = signature[offset] & 0x7f;
    if (lenBytesCount === 0 || lenBytesCount > 4) {
      throw new ConfigurationError('Invalid DER signature: invalid long-form length');
    }
    offset += 1 + lenBytesCount;
    if (offset > signature.length) {
      throw new ConfigurationError('Invalid DER signature: length bytes exceed signature length');
    }
  } else {
    offset += 1;
  }

  if (signature[offset] !== 0x02) {
    throw new ConfigurationError('Invalid DER signature: expected INTEGER for r');
  }
  const rLen = signature[offset + 1];
  offset += 2;
  let r = signature.slice(offset, offset + rLen);
  offset += rLen;

  if (signature[offset] !== 0x02) {
    throw new ConfigurationError('Invalid DER signature: expected INTEGER for s');
  }
  const sLen = signature[offset + 1];
  offset += 2;
  let s = signature.slice(offset, offset + sLen);

  if (r[0] === 0 && r.length > componentLen) {
    r = r.slice(1);
  }
  if (s[0] === 0 && s.length > componentLen) {
    s = s.slice(1);
  }

  const result = new Uint8Array(componentLen * 2);
  result.set(r, componentLen - r.length);
  result.set(s, componentLen * 2 - s.length);

  return result;
}

/**
 * Sign data with an asymmetric private key.
 */
export async function sign(
  data: Uint8Array,
  privateKey: PrivateKey,
  algorithm: AsymmetricSigningAlgorithm
): Promise<Uint8Array> {
  const { signParams } = getSigningAlgorithmParams(algorithm);
  const key = unwrapKey(privateKey);
  const signature = await crypto.subtle.sign(signParams, key, data);
  return ieeeP1363ToDer(new Uint8Array(signature), algorithm);
}

/**
 * Verify signature with an asymmetric public key.
 */
export async function verify(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: PublicKey,
  algorithm: AsymmetricSigningAlgorithm
): Promise<boolean> {
  const { signParams } = getSigningAlgorithmParams(algorithm);
  const key = unwrapKey(publicKey);
  const ieeeSignature = derToIeeeP1363(signature, algorithm);
  return crypto.subtle.verify(signParams, key, ieeeSignature, data);
}
