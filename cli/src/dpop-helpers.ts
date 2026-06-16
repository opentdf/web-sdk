// cli/src/dpop-helpers.ts
import { readFile } from 'node:fs/promises';
import { type webcrypto } from 'node:crypto';
import { type KeyPair, WebCryptoService } from '@opentdf/sdk/singlecontainer';
import { CLIError } from './logger.js';

const VALID_DPOP_ALGS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512'] as const;
export type DPoPAlg = (typeof VALID_DPOP_ALGS)[number];

const EC_CURVE_MAP: Record<string, string> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
};

/** Resolve the optional WebCryptoService.importPrivateKey method, failing with a clear CLIError if absent. */
function requireImportPrivateKey() {
  if (!WebCryptoService.importPrivateKey) {
    throw new CLIError(
      'CRITICAL',
      'WebCryptoService.importPrivateKey is unavailable in this SDK build; cannot load DPoP private keys'
    );
  }
  return WebCryptoService.importPrivateKey;
}

/** Convert a DER buffer to a PEM string with the given type label. */
export function derToPem(der: Uint8Array | ArrayBuffer, type: string): string {
  const bytes = der instanceof ArrayBuffer ? new Uint8Array(der) : der;
  const b64 = Buffer.from(bytes).toString('base64');
  const lines = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

/**
 * Generate an ephemeral DPoP key pair for the given JWS algorithm.
 * ES256/ES384/ES512 → ECDSA key via WebCrypto + SDK import.
 * RS256/RS384/RS512 → RSA-2048 via SDK's generateSigningKeyPair() (all map to RS256 in DPoP proof).
 */
export async function generateEphemeralDPoPKeyPair(alg: string): Promise<KeyPair> {
  if (!VALID_DPOP_ALGS.includes(alg as DPoPAlg)) {
    throw new CLIError(
      'CRITICAL',
      `Unsupported DPoP algorithm: ${alg}. Valid values: ${VALID_DPOP_ALGS.join(', ')}`
    );
  }

  if (alg === 'RS384' || alg === 'RS512') {
    console.warn(
      `[WARN] DPoP algorithm ${alg} requested but the SDK only supports RS256 for RSA keys; generating RSA-2048 (RS256) key.`
    );
  }

  const namedCurve = EC_CURVE_MAP[alg];
  if (namedCurve) {
    const raw = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, [
      'sign',
      'verify',
    ]);
    const [privDer, pubDer] = await Promise.all([
      crypto.subtle.exportKey('pkcs8', raw.privateKey),
      crypto.subtle.exportKey('spki', raw.publicKey),
    ]);
    const privPem = derToPem(privDer, 'PRIVATE KEY');
    const pubPem = derToPem(pubDer, 'PUBLIC KEY');
    const importPriv = requireImportPrivateKey();
    const [privateKey, publicKey] = await Promise.all([
      importPriv(privPem, { usage: 'sign', extractable: true }),
      WebCryptoService.importPublicKey(pubPem, { usage: 'sign', extractable: true }),
    ]);
    return { publicKey, privateKey };
  }

  // RSA fallback — generateSigningKeyPair() produces RSA-2048 (DPoP maps this to RS256)
  return WebCryptoService.generateSigningKeyPair();
}

/**
 * Load a DPoP key pair from a PKCS8 PEM-encoded private key file.
 * Derives the public key from the private key via JWK round-trip.
 * Supports ECDSA (P-256, P-384, P-521) and RSA (PKCS1-v1_5 SHA-256).
 */
export async function loadDPoPKeyPairFromPem(pemPath: string): Promise<KeyPair> {
  let privatePem: string;
  try {
    privatePem = await readFile(pemPath, 'utf8');
  } catch (err) {
    throw new CLIError('CRITICAL', `Cannot read DPoP key file: ${pemPath}`, err as Error);
  }

  let der: Uint8Array;
  try {
    const b64 = privatePem.replace(/-----[\w\s]+-----|[\r\n\s]/g, '');
    der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch (err) {
    throw new CLIError(
      'CRITICAL',
      `Cannot decode DPoP key file as PEM/base64: ${pemPath}. Ensure the file is a PKCS8 PEM-encoded private key.`,
      err as Error
    );
  }

  // Try EC curves (P-256, P-384, P-521). Catch only the importKey call so that
  // any SDK-layer errors from buildKeyPairFromCryptoKey propagate with full context.
  for (const namedCurve of ['P-256', 'P-384', 'P-521']) {
    let privCK: webcrypto.CryptoKey | undefined;
    try {
      privCK = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve }, true, [
        'sign',
      ]);
    } catch {
      // wrong curve or not an EC key — try next
    }
    if (privCK) {
      return await buildKeyPairFromCryptoKey(privatePem, privCK, { name: 'ECDSA', namedCurve });
    }
  }

  // Try RSA (PKCS1-v1_5 SHA-256). Same narrowing rationale as above.
  let rsaCK: webcrypto.CryptoKey | undefined;
  try {
    rsaCK = await crypto.subtle.importKey(
      'pkcs8',
      der,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['sign']
    );
  } catch {
    // not RSA either
  }
  if (rsaCK) {
    return await buildKeyPairFromCryptoKey(privatePem, rsaCK, {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    });
  }

  throw new CLIError(
    'CRITICAL',
    `Cannot parse DPoP key from ${pemPath}: expected PKCS8 PEM with ECDSA (P-256/P-384/P-521) or RSA private key`
  );
}

/**
 * Derive the public key from an already-imported private CryptoKey via JWK round-trip,
 * then import both through the SDK to get the opaque KeyPair type.
 */
async function buildKeyPairFromCryptoKey(
  privatePem: string,
  privCK: webcrypto.CryptoKey,
  algorithm:
    | webcrypto.AlgorithmIdentifier
    | webcrypto.RsaHashedImportParams
    | webcrypto.EcKeyImportParams
): Promise<KeyPair> {
  // Export private key as JWK; strip private components to build the public JWK
  const privJwk = await crypto.subtle.exportKey('jwk', privCK);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, p, q, dp, dq, qi, ...pubJwkProps } = privJwk;
  const pubJwk: webcrypto.JsonWebKey = { ...pubJwkProps, key_ops: ['verify'] };

  const pubCK = await crypto.subtle.importKey('jwk', pubJwk, algorithm, true, ['verify']);
  const pubDer = await crypto.subtle.exportKey('spki', pubCK);
  const pubPem = derToPem(pubDer, 'PUBLIC KEY');

  const importPriv = requireImportPrivateKey();
  const [privateKey, publicKey] = await Promise.all([
    importPriv(privatePem, { usage: 'sign', extractable: true }),
    WebCryptoService.importPublicKey(pubPem, { usage: 'sign', extractable: true }),
  ]);
  return { publicKey, privateKey };
}

/**
 * Main entry point: resolve a DPoP KeyPair from CLI arguments.
 * Returns undefined if DPoP is not requested.
 */
export async function resolveDPoPKeyPair(
  alg: string | undefined,
  keyPath: string | undefined
): Promise<KeyPair | undefined> {
  if (keyPath) {
    return loadDPoPKeyPairFromPem(keyPath);
  }
  if (alg) {
    return generateEphemeralDPoPKeyPair(alg);
  }
  return undefined;
}

/**
 * Resolve DPoP configuration from CLI argv. Bare `--dpop` defaults to ES256;
 * `--dpopKey` enables DPoP even without `--dpop`.
 */
export async function resolveDPoPFromArgs(argv: {
  dpop?: string;
  dpopKey?: string;
}): Promise<{ dpopEnabled: boolean; dpopKeyPair: KeyPair | undefined }> {
  const dpopAlg = argv.dpop === undefined ? undefined : argv.dpop || 'ES256';
  const dpopEnabled = dpopAlg !== undefined || !!argv.dpopKey;
  const dpopKeyPair = await resolveDPoPKeyPair(dpopAlg, argv.dpopKey);
  return { dpopEnabled, dpopKeyPair };
}
