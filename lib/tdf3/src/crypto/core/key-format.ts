import {
  ecAlgorithmToCurve,
  isEcKeyAlgorithm,
  isMlKemKeyAlgorithm,
  isRsaKeyAlgorithm,
  type KeyAlgorithm,
  type KeyOptions,
  MIN_ASYMMETRIC_KEY_SIZE_BITS,
  mlKemAlgorithmToLevel,
  type PrivateKey,
  type PublicKey,
  type PublicKeyInfo,
} from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';
import { formatAsPem, removePemFormatting } from '../crypto-utils.js';
import { encodeArrayBuffer as hexEncode } from '../../../../src/encodings/hex.js';
import { decodeArrayBuffer as base64Decode } from '../../../../src/encodings/base64.js';
import { exportSPKI, importX509 } from 'jose';
import {
  guessAlgorithmName,
  guessCurveName,
  toJwsAlg,
} from '../../../../src/crypto/pemPublicToCrypto.js';
import {
  unwrapKey,
  wrapMlKemPublicKey,
  unwrapMlKemKey,
  wrapPrivateKey,
  wrapPublicKey,
} from './keys.js';
import { bytesEqual, readTlv } from './asn1.js';
import { decodeMlKemSpkiDer, encodeMlKemSpkiDer, ML_KEM_OID_ARC_PREFIX } from './mlkem-asn1.js';
import { rsaOaepSha1 } from './rsa.js';

/**
 * Extract PEM public key from X.509 certificate or return PEM key as-is.
 */
export async function extractPublicKeyPem(
  certOrPem: string,
  jwaAlgorithm?: string
): Promise<string> {
  // If it's a certificate, extract the public key
  if (certOrPem.includes('-----BEGIN CERTIFICATE-----')) {
    let alg = jwaAlgorithm;
    if (!alg) {
      // Auto-detect algorithm from certificate OIDs
      const certBody = certOrPem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, '');
      const certBytes = base64Decode(certBody);
      const hex = hexEncode(certBytes);
      alg = toJwsAlg(hex);
    }
    const cert = await importX509(certOrPem, alg, { extractable: true });
    return exportSPKI(cert);
  }

  // If it's already a PEM public key, return as-is
  if (certOrPem.includes('-----BEGIN PUBLIC KEY-----')) {
    return certOrPem;
  }

  throw new ConfigurationError('Input must be a PEM-encoded certificate or public key');
}

/**
 * Decode base64url string and return byte length.
 * Uses the existing base64 decoder which handles both standard and URL-safe encoding.
 */
function base64urlByteLength(base64url: string): number {
  // Add padding if needed (base64url omits padding)
  const padding = (4 - (base64url.length % 4)) % 4;
  const padded = base64url + '='.repeat(padding);
  return base64Decode(padded).byteLength;
}

// DER OID *content* bytes (tag/length stripped), as returned by readTlv. These are
// the byte twins of the hex OID constants in pemPublicToCrypto.ts.
const RSA_OID = Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01); // 1.2.840.113549.1.1.1
const EC_OID = Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01); // 1.2.840.10045.2.1 (id-ecPublicKey)
const P256_OID = Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07); // 1.2.840.10045.3.1.7
const P384_OID = Uint8Array.of(0x2b, 0x81, 0x04, 0x00, 0x22); // 1.3.132.0.34
const P521_OID = Uint8Array.of(0x2b, 0x81, 0x04, 0x00, 0x23); // 1.3.132.0.35

/**
 * Read a SubjectPublicKeyInfo's algorithm OID (and, for EC, the following curve
 * parameter OID) directly from its DER bytes:
 *
 *   SEQUENCE { AlgorithmIdentifier SEQUENCE { OID algorithm, ANY parameters }, BIT STRING key }
 *
 * Reading the OID from its exact structural position — rather than substring
 * matching hex-encoded key bytes — avoids incidental and nibble-misaligned
 * matches against key material.
 */
function readSpkiAlgorithm(der: Uint8Array): { algorithmOid: Uint8Array; curveOid?: Uint8Array } {
  const spki = readTlv(der, 0);
  if (spki.tag !== 0x30) throw new ConfigurationError('Invalid SPKI: missing outer SEQUENCE');
  const algId = readTlv(der, spki.contentStart);
  if (algId.tag !== 0x30) throw new ConfigurationError('Invalid SPKI: missing AlgorithmIdentifier');
  const oid = readTlv(der, algId.contentStart);
  if (oid.tag !== 0x06) throw new ConfigurationError('Invalid SPKI: missing algorithm OID');
  const algorithmOid = der.subarray(oid.contentStart, oid.contentEnd);

  // AlgorithmIdentifier parameters follow the OID. For EC keys this is the named
  // curve OID; for RSA it is NULL; for ML-KEM it is absent.
  let curveOid: Uint8Array | undefined;
  if (oid.next < algId.contentEnd) {
    const param = readTlv(der, oid.next);
    if (param.tag === 0x06) curveOid = der.subarray(param.contentStart, param.contentEnd);
  }
  return { algorithmOid, curveOid };
}

/**
 * Extract RSA modulus bit length by importing key and exporting as JWK.
 * Uses Web Crypto's built-in ASN.1 parsing for robustness.
 */
async function extractRsaModulusBitLength(keyData: ArrayBuffer): Promise<number> {
  const key = await crypto.subtle.importKey(
    'spki',
    keyData,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (!jwk.n) {
    throw new ConfigurationError('Invalid RSA key: missing modulus');
  }
  // JWK 'n' is base64url-encoded modulus
  // Decode and count bytes, multiply by 8 for bits
  return base64urlByteLength(jwk.n) * 8;
}

/**
 * Import and validate a PEM public key, returning algorithm info.
 * Uses JWK export for robust key parameter detection.
 */
export async function parsePublicKeyPem(pem: string): Promise<PublicKeyInfo> {
  // First extract public key if it's a certificate
  let publicKeyPem = pem;
  if (pem.includes('-----BEGIN CERTIFICATE-----')) {
    publicKeyPem = await extractPublicKeyPem(pem);
  }

  if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
    throw new ConfigurationError('Input must be a PEM-encoded public key or certificate');
  }

  const der = new Uint8Array(base64Decode(removePemFormatting(publicKeyPem)));
  const { algorithmOid, curveOid } = readSpkiAlgorithm(der);

  // ML-KEM: WebCrypto has no support (as of 2026). Route by the id-alg-ml-kem arc,
  // then let decodeMlKemSpkiDer validate structure/length and report the level.
  if (algorithmOid.length === 9 && bytesEqual(algorithmOid.subarray(0, 8), ML_KEM_OID_ARC_PREFIX)) {
    const { level } = decodeMlKemSpkiDer(der);
    return { algorithm: `mlkem:${level}` as const, pem: publicKeyPem };
  }

  if (bytesEqual(algorithmOid, RSA_OID)) {
    // Use JWK export to read the modulus size.
    const modulusBits = await extractRsaModulusBitLength(der.buffer);
    let algorithm: PublicKeyInfo['algorithm'];
    if (modulusBits < MIN_ASYMMETRIC_KEY_SIZE_BITS) {
      throw new ConfigurationError(
        `RSA key size ${modulusBits} bits is below the minimum of ${MIN_ASYMMETRIC_KEY_SIZE_BITS} bits`
      );
    } else if (modulusBits <= 2048) {
      algorithm = 'rsa:2048';
    } else if (modulusBits <= 4096) {
      algorithm = 'rsa:4096';
    } else {
      throw new ConfigurationError(`Unsupported RSA key size: ${modulusBits} bits`);
    }
    return { algorithm, pem: publicKeyPem };
  }

  if (bytesEqual(algorithmOid, EC_OID) && curveOid) {
    if (bytesEqual(curveOid, P256_OID)) return { algorithm: 'ec:secp256r1', pem: publicKeyPem };
    if (bytesEqual(curveOid, P384_OID)) return { algorithm: 'ec:secp384r1', pem: publicKeyPem };
    if (bytesEqual(curveOid, P521_OID)) return { algorithm: 'ec:secp521r1', pem: publicKeyPem };
  }

  throw new ConfigurationError('Unable to determine public key algorithm - unsupported key type');
}

/**
 * Convert a JWK (JSON Web Key) to PEM format.
 */
export async function jwkToPublicKeyPem(jwk: JsonWebKey): Promise<string> {
  let key: CryptoKey;

  if (jwk.kty === 'RSA') {
    // RSA key
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
      'encrypt',
    ]);
  } else if (jwk.kty === 'EC') {
    // EC key
    const crv = jwk.crv;
    if (!crv || !['P-256', 'P-384', 'P-521'].includes(crv)) {
      throw new ConfigurationError(`Unsupported EC curve: ${crv}`);
    }
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: crv }, true, []);
  } else {
    throw new ConfigurationError(`Unsupported JWK key type: ${jwk.kty}`);
  }

  const spkiBuffer = await crypto.subtle.exportKey('spki', key);
  return formatAsPem(spkiBuffer, 'PUBLIC KEY');
}

/**
 * Convert a PEM public key to JWK format.
 * Returns only public key components (no private key data).
 */
export async function publicKeyPemToJwk(publicKeyPem: string): Promise<JsonWebKey> {
  const keyDataBase64 = removePemFormatting(publicKeyPem);
  const keyBuffer = base64Decode(keyDataBase64);
  const hex = hexEncode(keyBuffer);

  // Detect key type using OID
  const algorithmName = guessAlgorithmName(hex);

  if (algorithmName === 'ECDH' || algorithmName === 'ECDSA') {
    // EC key - detect curve from OID
    const namedCurve = guessCurveName(hex);
    const key = await crypto.subtle.importKey(
      'spki',
      keyBuffer,
      { name: 'ECDSA', namedCurve },
      true,
      ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);
    // Return only public key components
    const { kty, crv, x, y } = jwk;
    return { kty, crv, x, y };
  } else {
    // RSA key
    const key = await crypto.subtle.importKey(
      'spki',
      keyBuffer,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);
    // Return only public key components
    const { kty, e, n } = jwk;
    return { kty, e, n };
  }
}

/**
 * Import a PEM public key as an opaque key.
 *
 * Accepts standard `-----BEGIN PUBLIC KEY-----` SPKI envelopes for RSA, EC, and
 * ML-KEM (per draft-ietf-lamps-kyber-certificates, OIDs id-alg-ml-kem-{768,1024}).
 * ML-KEM keys produced by `openssl pkey -pubout` round-trip without translation.
 */
export async function importPublicKey(pem: string, options: KeyOptions): Promise<PublicKey> {
  const { usage = 'encrypt', extractable = true, algorithmHint } = options;

  // Detect algorithm from PEM; also normalises certificates → plain SPKI PEM
  // and identifies ML-KEM keys by OID.
  const keyInfo = await parsePublicKeyPem(pem);

  // ML-KEM: import via SPKI codec. WebCrypto has no ML-KEM support, so we keep
  // the key as an opaque `PublicKey` carrying the raw encapsulation key bytes.
  if (isMlKemKeyAlgorithm(keyInfo.algorithm)) {
    const der = new Uint8Array(base64Decode(removePemFormatting(keyInfo.pem)));
    const { level, rawKey } = decodeMlKemSpkiDer(der);
    if (algorithmHint && algorithmHint !== `mlkem:${level}`) {
      throw new ConfigurationError(
        `ML-KEM SPKI advertises mlkem:${level} but algorithmHint is ${algorithmHint}`
      );
    }
    return wrapMlKemPublicKey(rawKey, level);
  }

  const algorithm = algorithmHint || keyInfo.algorithm;
  // Use keyInfo.pem (normalised SPKI) not the original pem, which may be a certificate.
  // Passing raw X.509 DER bytes to crypto.subtle.importKey('spki') would throw DataError.
  const keyData = removePemFormatting(keyInfo.pem);
  const keyBuffer = base64Decode(keyData);

  // Determine Web Crypto algorithm and usages based on key type and usage
  let cryptoAlgorithm: RsaHashedImportParams | EcKeyImportParams;
  let keyUsages: KeyUsage[];

  if (isRsaKeyAlgorithm(algorithm)) {
    if (usage === 'encrypt') {
      cryptoAlgorithm = rsaOaepSha1();
      keyUsages = ['encrypt'];
    } else if (usage === 'sign') {
      cryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      keyUsages = ['verify'];
    } else {
      throw new ConfigurationError('RSA keys only support usage: encrypt or sign');
    }
  } else if (isEcKeyAlgorithm(algorithm)) {
    const namedCurve = ecAlgorithmToCurve(algorithm);

    if (usage === 'derive') {
      cryptoAlgorithm = { name: 'ECDH', namedCurve };
      keyUsages = [];
    } else if (usage === 'sign') {
      cryptoAlgorithm = { name: 'ECDSA', namedCurve };
      keyUsages = ['verify'];
    } else {
      throw new ConfigurationError('EC keys only support usage: derive or sign');
    }
  } else {
    throw new ConfigurationError(`Unsupported algorithm: ${algorithm}`);
  }

  // Import as CryptoKey
  const cryptoKey = await crypto.subtle.importKey(
    'spki',
    keyBuffer,
    cryptoAlgorithm,
    extractable,
    keyUsages
  );

  return wrapPublicKey(cryptoKey, algorithm);
}

/**
 * Import a PEM private key as an opaque key.
 */
export async function importPrivateKey(pem: string, options: KeyOptions): Promise<PrivateKey> {
  const { usage = 'encrypt', extractable = true, algorithmHint } = options;

  // Detect algorithm from PEM structure (similar to public key detection)
  // For now, use algorithmHint if provided, otherwise detect from key structure
  let algorithm: KeyAlgorithm;

  const keyData = removePemFormatting(pem);
  const keyBuffer = base64Decode(keyData);

  if (algorithmHint) {
    algorithm = algorithmHint;
  } else {
    // PKCS#8 PrivateKeyInfo embeds the same AlgorithmIdentifier OIDs as SPKI,
    // so guessAlgorithmName / guessCurveName work on private key bytes too.
    const hex = hexEncode(keyBuffer);
    const algorithmName = guessAlgorithmName(hex); // throws on unrecognised OID
    if (algorithmName === 'ECDH' || algorithmName === 'ECDSA') {
      const namedCurve = guessCurveName(hex);
      const curveMap: Record<string, KeyAlgorithm> = {
        'P-256': 'ec:secp256r1',
        'P-384': 'ec:secp384r1',
        'P-521': 'ec:secp521r1',
      };
      const mapped = curveMap[namedCurve];
      if (!mapped)
        throw new ConfigurationError(`Unsupported EC curve in private key: ${namedCurve}`);
      algorithm = mapped;
    } else {
      // RSA — determine key size by importing and reading modulus length from JWK
      const tempKey = await crypto.subtle.importKey(
        'pkcs8',
        keyBuffer,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        true,
        ['sign']
      );
      const jwk = await crypto.subtle.exportKey('jwk', tempKey);
      if (!jwk.n) {
        throw new ConfigurationError('Invalid RSA private key: missing modulus');
      }
      const modulusBits = base64urlByteLength(jwk.n) * 8;
      if (modulusBits < MIN_ASYMMETRIC_KEY_SIZE_BITS) {
        throw new ConfigurationError(
          `RSA key size ${modulusBits} bits is below the minimum of ${MIN_ASYMMETRIC_KEY_SIZE_BITS} bits`
        );
      }
      algorithm = modulusBits <= 2048 ? 'rsa:2048' : 'rsa:4096';
    }
  }

  // Determine Web Crypto algorithm and usages
  let cryptoAlgorithm: RsaHashedImportParams | EcKeyImportParams;
  let keyUsages: KeyUsage[];

  if (isRsaKeyAlgorithm(algorithm)) {
    if (usage === 'encrypt') {
      cryptoAlgorithm = rsaOaepSha1();
      keyUsages = ['decrypt'];
    } else if (usage === 'sign') {
      cryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      keyUsages = ['sign'];
    } else {
      throw new ConfigurationError('RSA keys only support usage: encrypt or sign');
    }
  } else if (isEcKeyAlgorithm(algorithm)) {
    const namedCurve = ecAlgorithmToCurve(algorithm);

    if (usage === 'derive') {
      cryptoAlgorithm = { name: 'ECDH', namedCurve };
      keyUsages = ['deriveBits'];
    } else if (usage === 'sign') {
      cryptoAlgorithm = { name: 'ECDSA', namedCurve };
      keyUsages = ['sign'];
    } else {
      throw new ConfigurationError('EC keys only support usage: derive or sign');
    }
  } else {
    throw new ConfigurationError(`Unsupported algorithm: ${algorithm}`);
  }

  // Import as CryptoKey
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    keyBuffer,
    cryptoAlgorithm,
    extractable,
    keyUsages
  );

  return wrapPrivateKey(cryptoKey, algorithm);
}

/**
 * Export an opaque public key to PEM SPKI format.
 *
 * ML-KEM keys are wrapped in a SubjectPublicKeyInfo envelope using the NIST
 * OIDs id-alg-ml-kem-{768,1024} (per draft-ietf-lamps-kyber-certificates),
 * so the resulting PEM is byte-compatible with `openssl pkey -pubout`.
 */
export async function exportPublicKeyPem(key: PublicKey): Promise<string> {
  if (isMlKemKeyAlgorithm(key.algorithm)) {
    const level = mlKemAlgorithmToLevel(key.algorithm);
    const der = encodeMlKemSpkiDer(unwrapMlKemKey(key), level);
    return formatAsPem(
      der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength),
      'PUBLIC KEY'
    );
  }
  const cryptoKey = unwrapKey(key);
  const keyBuffer = await crypto.subtle.exportKey('spki', cryptoKey);
  return formatAsPem(keyBuffer, 'PUBLIC KEY');
}

/**
 * Export an opaque private key to PEM format.
 * ONLY USE FOR TESTING/DEVELOPMENT. Private keys should NOT be exportable in secure environments.
 */
export async function exportPrivateKeyPem(key: PrivateKey): Promise<string> {
  const cryptoKey = unwrapKey(key);
  const keyBuffer = await crypto.subtle.exportKey('pkcs8', cryptoKey);
  return formatAsPem(keyBuffer, 'PRIVATE KEY');
}

/**
 * Export an opaque public key to JWK format.
 */
export async function exportPublicKeyJwk(key: PublicKey): Promise<JsonWebKey> {
  const cryptoKey = unwrapKey(key);
  return await crypto.subtle.exportKey('jwk', cryptoKey);
}
