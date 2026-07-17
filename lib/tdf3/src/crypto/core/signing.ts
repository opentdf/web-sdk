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

/** Fixed-width byte length of each ECDSA signature component (R or S). */
function getEcdsaComponentLength(algorithm: AsymmetricSigningAlgorithm): number {
  switch (algorithm) {
    case 'ES256':
      return 32;
    case 'ES384':
      return 48;
    case 'ES512':
      return 66;
    default:
      throw new ConfigurationError(`Unsupported algorithm for ECDSA conversion: ${algorithm}`);
  }
}

/**
 * Convert IEEE P1363 signature format (used by WebCrypto ECDSA) to DER format.
 * RS256 signatures don't need conversion.
 */
export function ieeeP1363ToDer(
  signature: Uint8Array,
  algorithm: AsymmetricSigningAlgorithm
): Uint8Array {
  if (algorithm === 'RS256') {
    return signature;
  }

  const componentLen = getEcdsaComponentLength(algorithm);
  const expectedLength = componentLen * 2;
  if (signature.length !== expectedLength) {
    throw new ConfigurationError(
      `Invalid IEEE P1363 signature: expected ${expectedLength} bytes for ${algorithm}, got ${signature.length}`
    );
  }

  // IEEE P1363: r || s where each is padded to key size
  const r = signature.slice(0, componentLen);
  const s = signature.slice(componentLen);

  // Remove leading zeros but keep one if the high bit is set
  const trimLeadingZeros = (arr: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < arr.length - 1 && arr[i] === 0) i++;
    return arr.slice(i);
  };

  let rTrimmed = trimLeadingZeros(r);
  let sTrimmed = trimLeadingZeros(s);

  // Add leading zero if high bit is set (to keep positive in DER)
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

  // DER SEQUENCE: 0x30 [length] [r INTEGER] [s INTEGER]
  // INTEGER: 0x02 [length] [value]
  const rDer = new Uint8Array([0x02, rTrimmed.length, ...rTrimmed]);
  const sDer = new Uint8Array([0x02, sTrimmed.length, ...sTrimmed]);

  const seqLen = rDer.length + sDer.length;
  // DER length: short-form for < 128, long-form (0x81 nn) for 128-255.
  // ECDSA sequences never exceed 255 bytes for any supported curve.
  const lenBytes = seqLen < 128 ? new Uint8Array([seqLen]) : new Uint8Array([0x81, seqLen]);
  const result = new Uint8Array(1 + lenBytes.length + seqLen);
  result[0] = 0x30;
  result.set(lenBytes, 1);
  result.set(rDer, 1 + lenBytes.length);
  result.set(sDer, 1 + lenBytes.length + rDer.length);

  return result;
}

/**
 * Convert DER-encoded ECDSA signature to raw IEEE P1363 (R||S) format.
 * RS256 signatures pass through unchanged.
 *
 * Exported because callers that emit JWS (e.g. DPoP proofs in lib/src/auth/dpop.ts)
 * must produce raw R||S per RFC 7518 §3.4, while cryptoService.sign() currently
 * returns DER. See DSPX-3634 for the broader cleanup.
 */
export function derToIeeeP1363(
  signature: Uint8Array,
  algorithm: AsymmetricSigningAlgorithm
): Uint8Array {
  if (algorithm === 'RS256') {
    return signature;
  }

  const componentLen = getEcdsaComponentLength(algorithm);

  // Smallest well-formed ECDSA DER SEQUENCE is 8 bytes:
  //   0x30 seqLen 0x02 rLen r(>=1) 0x02 sLen s(>=1)
  // Anything shorter cannot be parsed; reject before indexing so a malformed
  // input throws a clean ConfigurationError rather than coercing undefined.
  if (signature.length < 8) {
    throw new ConfigurationError('Invalid DER signature: too short');
  }

  if (signature[0] !== 0x30) {
    throw new ConfigurationError('Invalid DER signature: expected SEQUENCE');
  }

  // Skip SEQUENCE tag, then parse DER length (short- or long-form).
  let offset = 1;
  if (signature[offset] & 0x80) {
    // Long-form: low 7 bits = number of subsequent length bytes.
    const lenBytesCount = signature[offset] & 0x7f;
    if (lenBytesCount === 0 || lenBytesCount > 4) {
      throw new ConfigurationError('Invalid DER signature: invalid long-form length');
    }
    offset += 1 + lenBytesCount;
  } else {
    // Short-form: single length byte.
    offset += 1;
  }

  // Parse a DER INTEGER at `offset`, advancing past it. Every read is
  // bounds-checked so a truncated or over-long length field throws a clean
  // ConfigurationError instead of silently slicing a short/empty component.
  const readInteger = (label: 'r' | 's'): Uint8Array => {
    if (offset + 1 >= signature.length) {
      throw new ConfigurationError(`Invalid DER signature: truncated before ${label} INTEGER`);
    }
    if (signature[offset] !== 0x02) {
      throw new ConfigurationError(`Invalid DER signature: expected INTEGER for ${label}`);
    }
    const len = signature[offset + 1];
    const start = offset + 2;
    const end = start + len;
    if (len === 0 || end > signature.length) {
      throw new ConfigurationError(`Invalid DER signature: ${label} INTEGER length out of range`);
    }
    offset = end;
    return signature.slice(start, end);
  };

  let r = readInteger('r');
  let s = readInteger('s');

  // Strip DER's leading zero padding (INTEGERs are zero-prefixed to stay positive).
  const stripLeadingZeros = (arr: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < arr.length - 1 && arr[i] === 0) i++;
    return arr.slice(i);
  };
  r = stripLeadingZeros(r);
  s = stripLeadingZeros(s);

  // After stripping, each component must fit its fixed-width slot; a larger value
  // means the signature does not belong to this curve (and would otherwise produce
  // a negative offset in result.set below).
  if (r.length > componentLen || s.length > componentLen) {
    throw new ConfigurationError('Invalid DER signature: component larger than expected for curve');
  }

  // Pad to component length (right-aligned): result = r_padded || s_padded.
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

  // Unwrap the internal CryptoKey
  const key = unwrapKey(privateKey);

  // Sign the data
  const signature = await crypto.subtle.sign(signParams, key, data);

  // Convert from IEEE P1363 to DER for EC algorithms
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

  // Unwrap the internal CryptoKey
  const key = unwrapKey(publicKey);

  // Convert from DER to IEEE P1363 for EC algorithms
  const ieeeSignature = derToIeeeP1363(signature, algorithm);

  // Verify the signature
  return crypto.subtle.verify(signParams, key, ieeeSignature, data);
}
