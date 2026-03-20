import {
  type KeyAlgorithm,
  type KeyOptions,
  MIN_ASYMMETRIC_KEY_SIZE_BITS,
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
import { unwrapKey, wrapPrivateKey, wrapPublicKey } from './keys.js';
import { rsaOaepSha1 } from './rsa.js';

/**
 * Extract PEM public key from X.509 certificate or return PEM key as-is.
 */
export async function extractPublicKeyPem(
  certOrPem: string,
  jwaAlgorithm?: string
): Promise<string> {
  if (certOrPem.includes('-----BEGIN CERTIFICATE-----')) {
    let alg = jwaAlgorithm;
    if (!alg) {
      const certBody = certOrPem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, '');
      const certBytes = base64Decode(certBody);
      const hex = hexEncode(certBytes);
      alg = toJwsAlg(hex);
    }
    const cert = await importX509(certOrPem, alg, { extractable: true });
    return exportSPKI(cert);
  }

  if (certOrPem.includes('-----BEGIN PUBLIC KEY-----')) {
    return certOrPem;
  }

  throw new ConfigurationError('Input must be a PEM-encoded certificate or public key');
}

const SUPPORTED_EC_CURVES = ['P-256', 'P-384', 'P-521'] as const;
type SupportedEcCurve = (typeof SUPPORTED_EC_CURVES)[number];

/**
 * Decode base64url string and return byte length.
 */
function base64urlByteLength(base64url: string): number {
  const padding = (4 - (base64url.length % 4)) % 4;
  const padded = base64url + '='.repeat(padding);
  return base64Decode(padded).byteLength;
}

/**
 * Extract EC curve from a public key by parsing ASN.1 OIDs.
 */
function extractEcCurveFromPublicKey(keyData: ArrayBuffer): SupportedEcCurve {
  const hexKey = hexEncode(keyData);
  const curveName = guessCurveName(hexKey);
  return curveName as SupportedEcCurve;
}

/**
 * Extract RSA modulus bit length by importing key and exporting as JWK.
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
  return base64urlByteLength(jwk.n) * 8;
}

/**
 * Import and validate a PEM public key, returning algorithm info.
 */
export async function parsePublicKeyPem(pem: string): Promise<PublicKeyInfo> {
  let publicKeyPem = pem;
  if (pem.includes('-----BEGIN CERTIFICATE-----')) {
    publicKeyPem = await extractPublicKeyPem(pem);
  }

  if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
    throw new ConfigurationError('Input must be a PEM-encoded public key or certificate');
  }

  const keyData = base64Decode(removePemFormatting(publicKeyPem));

  try {
    const modulusBits = await extractRsaModulusBitLength(keyData);
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
  } catch (error) {
    if (error instanceof ConfigurationError) {
      throw error;
    }
  }

  try {
    const detectedCurve = extractEcCurveFromPublicKey(keyData);
    const curveMap = {
      'P-256': 'ec:secp256r1',
      'P-384': 'ec:secp384r1',
      'P-521': 'ec:secp521r1',
    } as const;
    return { algorithm: curveMap[detectedCurve], pem: publicKeyPem };
  } catch {
    // Not a valid EC key
  }

  throw new ConfigurationError('Unable to determine public key algorithm - unsupported key type');
}

/**
 * Convert a JWK (JSON Web Key) to PEM format.
 */
export async function jwkToPublicKeyPem(jwk: JsonWebKey): Promise<string> {
  let key: CryptoKey;

  if (jwk.kty === 'RSA') {
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
      'encrypt',
    ]);
  } else if (jwk.kty === 'EC') {
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

  const algorithmName = guessAlgorithmName(hex);

  if (algorithmName === 'ECDH' || algorithmName === 'ECDSA') {
    const namedCurve = guessCurveName(hex);
    const key = await crypto.subtle.importKey(
      'spki',
      keyBuffer,
      { name: 'ECDSA', namedCurve },
      true,
      ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);
    const { kty, crv, x, y } = jwk;
    return { kty, crv, x, y };
  }

  const key = await crypto.subtle.importKey(
    'spki',
    keyBuffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify']
  );
  const jwk = await crypto.subtle.exportKey('jwk', key);
  const { kty, e, n } = jwk;
  return { kty, e, n };
}

/**
 * Import a PEM public key as an opaque key.
 */
export async function importPublicKey(pem: string, options: KeyOptions): Promise<PublicKey> {
  const { usage = 'encrypt', extractable = true, algorithmHint } = options;

  const keyInfo = await parsePublicKeyPem(pem);
  const algorithm = algorithmHint || keyInfo.algorithm;
  const keyData = removePemFormatting(keyInfo.pem);
  const keyBuffer = base64Decode(keyData);

  let cryptoAlgorithm: RsaHashedImportParams | EcKeyImportParams;
  let keyUsages: KeyUsage[];

  if (algorithm.startsWith('rsa:')) {
    if (usage === 'encrypt') {
      cryptoAlgorithm = rsaOaepSha1();
      keyUsages = ['encrypt'];
    } else if (usage === 'sign') {
      cryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      keyUsages = ['verify'];
    } else {
      throw new ConfigurationError('RSA keys only support usage: encrypt or sign');
    }
  } else if (algorithm.startsWith('ec:')) {
    const curve = algorithm.split(':')[1];
    const namedCurve =
      curve === 'secp256r1'
        ? 'P-256'
        : curve === 'secp384r1'
          ? 'P-384'
          : curve === 'secp521r1'
            ? 'P-521'
            : (() => {
                throw new ConfigurationError(`Unsupported EC curve: ${curve}`);
              })();

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

  let algorithm: KeyAlgorithm;

  const keyData = removePemFormatting(pem);
  const keyBuffer = base64Decode(keyData);

  if (algorithmHint) {
    algorithm = algorithmHint;
  } else {
    const hex = hexEncode(keyBuffer);
    const algorithmName = guessAlgorithmName(hex);
    if (algorithmName === 'ECDH' || algorithmName === 'ECDSA') {
      const namedCurve = guessCurveName(hex);
      const curveMap: Record<string, KeyAlgorithm> = {
        'P-256': 'ec:secp256r1',
        'P-384': 'ec:secp384r1',
        'P-521': 'ec:secp521r1',
      };
      const mapped = curveMap[namedCurve];
      if (!mapped) {
        throw new ConfigurationError(`Unsupported EC curve in private key: ${namedCurve}`);
      }
      algorithm = mapped;
    } else {
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

  let cryptoAlgorithm: RsaHashedImportParams | EcKeyImportParams;
  let keyUsages: KeyUsage[];

  if (algorithm.startsWith('rsa:')) {
    if (usage === 'encrypt') {
      cryptoAlgorithm = rsaOaepSha1();
      keyUsages = ['decrypt'];
    } else if (usage === 'sign') {
      cryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      keyUsages = ['sign'];
    } else {
      throw new ConfigurationError('RSA keys only support usage: encrypt or sign');
    }
  } else if (algorithm.startsWith('ec:')) {
    const curve = algorithm.split(':')[1];
    const namedCurve =
      curve === 'secp256r1'
        ? 'P-256'
        : curve === 'secp384r1'
          ? 'P-384'
          : curve === 'secp521r1'
            ? 'P-521'
            : (() => {
                throw new ConfigurationError(`Unsupported EC curve: ${curve}`);
              })();

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
 * Export an opaque public key to PEM format.
 */
export async function exportPublicKeyPem(key: PublicKey): Promise<string> {
  const cryptoKey = unwrapKey(key);
  const keyBuffer = await crypto.subtle.exportKey('spki', cryptoKey);
  return formatAsPem(keyBuffer, 'PUBLIC KEY');
}

/**
 * Export an opaque private key to PEM format.
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
