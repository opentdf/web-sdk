// cli/src/dpop-helpers.ts
import { readFile } from 'node:fs/promises';
import { type webcrypto } from 'node:crypto';
import { base64 } from '@opentdf/sdk/encodings';
import { type KeyPair, WebCryptoService } from '@opentdf/sdk/singlecontainer';
import { CLIError, log } from './logger.js';

export const VALID_DPOP_ALGS = ['ES256', 'ES384', 'ES512', 'RS256'] as const;
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
 * RS256 → RSA-2048 via the SDK's generateSigningKeyPair().
 * RS384/RS512 are not supported (the SDK signs all RSA DPoP proofs as RS256) and
 * are rejected rather than silently downgraded.
 */
export async function generateEphemeralDPoPKeyPair(alg: string): Promise<KeyPair> {
  if (!VALID_DPOP_ALGS.includes(alg as DPoPAlg)) {
    throw new CLIError(
      'CRITICAL',
      `Unsupported DPoP algorithm: ${alg}. Valid values: ${VALID_DPOP_ALGS.join(', ')}`
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
  // Retain the most recent import failure so a genuinely corrupt key surfaces its
  // real decode error as the cause, instead of only the generic "unsupported" message.
  let lastImportError: unknown;
  for (const namedCurve of ['P-256', 'P-384', 'P-521']) {
    let privCK: webcrypto.CryptoKey | undefined;
    try {
      privCK = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve }, true, [
        'sign',
      ]);
    } catch (err) {
      lastImportError = err;
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
  } catch (err) {
    lastImportError = err;
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
    `Cannot parse DPoP key from ${pemPath}: expected PKCS8 PEM with ECDSA (P-256/P-384/P-521) or RSA private key`,
    lastImportError instanceof Error ? lastImportError : undefined
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
    webcrypto.AlgorithmIdentifier | webcrypto.RsaHashedImportParams | webcrypto.EcKeyImportParams
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
 * The opaque key `algorithm` string the SDK reports for a key of each DPoP JWS
 * algorithm. EC curves are matched exactly; all RSA key sizes sign as RS256, so
 * RS256 matches the `rsa` family (e.g. `rsa:2048`, `rsa:4096`).
 */
const DPOP_ALG_TO_KEY_ALG: Record<DPoPAlg, string> = {
  ES256: 'ec:secp256r1',
  ES384: 'ec:secp384r1',
  ES512: 'ec:secp521r1',
  RS256: 'rsa',
};

/**
 * Throw if a loaded key's algorithm doesn't satisfy an explicitly-requested
 * `--dpop-alg` algorithm, so the CLI never silently signs with a different (possibly
 * weaker) algorithm than the user asked for.
 */
function assertKeyMatchesRequestedAlg(keyPair: KeyPair, alg: string, keyPath: string): void {
  if (!VALID_DPOP_ALGS.includes(alg as DPoPAlg)) {
    throw new CLIError(
      'CRITICAL',
      `Unsupported DPoP algorithm: ${alg}. Valid values: ${VALID_DPOP_ALGS.join(', ')}`
    );
  }
  const expected = DPOP_ALG_TO_KEY_ALG[alg as DPoPAlg];
  const actual = keyPair.publicKey.algorithm;
  const matches = expected === 'rsa' ? actual.startsWith('rsa') : actual === expected;
  if (!matches) {
    throw new CLIError(
      'CRITICAL',
      `--dpop-alg=${alg} conflicts with the key in --dpopKey (${keyPath}): the key's algorithm is ` +
        `${actual}. Remove --dpop-alg to infer the algorithm from the key, or supply a key matching ${alg}.`
    );
  }
}

/**
 * Main entry point: resolve a DPoP KeyPair from CLI arguments.
 * Returns undefined if DPoP is not requested. When a key file is supplied, its
 * algorithm is inferred from the key; an explicitly-requested `--dpop-alg` algorithm
 * that disagrees with the key is a hard error (see {@link assertKeyMatchesRequestedAlg}).
 */
export async function resolveDPoPKeyPair(
  alg: string | undefined,
  keyPath: string | undefined,
  algWasExplicit = false
): Promise<KeyPair | undefined> {
  if (keyPath) {
    const keyPair = await loadDPoPKeyPairFromPem(keyPath);
    if (alg && algWasExplicit) {
      assertKeyMatchesRequestedAlg(keyPair, alg, keyPath);
    }
    return keyPair;
  }
  if (alg) {
    return generateEphemeralDPoPKeyPair(alg);
  }
  return undefined;
}

/**
 * Resolve DPoP configuration from CLI argv. `--dpop` enables DPoP with an ES256
 * ephemeral key; `--dpop-alg` picks a different ephemeral algorithm (or, with
 * `--dpopKey`, the algorithm the key must match); `--dpopKey` loads a key and
 * infers its algorithm. Either of the latter two enables DPoP without `--dpop`.
 */
export async function resolveDPoPFromArgs(argv: {
  dpop?: boolean;
  dpopAlg?: string;
  dpopKey?: string;
}): Promise<{ dpopEnabled: boolean; dpopKeyPair: KeyPair | undefined }> {
  if (argv.dpop === false && (argv.dpopAlg || argv.dpopKey)) {
    throw new CLIError('CRITICAL', '--no-dpop conflicts with --dpop-alg and --dpopKey');
  }
  const dpopEnabled = !!argv.dpop || !!argv.dpopAlg || !!argv.dpopKey;
  if (!dpopEnabled) {
    return { dpopEnabled, dpopKeyPair: undefined };
  }
  const dpopAlg = argv.dpopAlg || (argv.dpopKey ? undefined : 'ES256');
  const dpopKeyPair = await resolveDPoPKeyPair(dpopAlg, argv.dpopKey, !!argv.dpopAlg);
  return { dpopEnabled, dpopKeyPair };
}

const parseJwt = (jwt: string, field = 1) => {
  return JSON.parse(base64.decode(jwt.split('.')[field])) as unknown;
};

const parseJwtComplete = (jwt: string) => {
  return { header: parseJwt(jwt, 0), payload: parseJwt(jwt) };
};

/**
 * Check the credentials on the last authenticated request: an access token must
 * be present, and with DPoP enabled it must be bound (`cnf.jkt`) and accompanied
 * by a proof. Run this before writing any decrypted output, so a binding failure
 * never leaves plaintext behind with a non-zero exit.
 */
export function assertRequestBinding(
  request: { headers: Record<string, string> } | undefined,
  dpopEnabled: boolean
): void {
  log('SILLY', `last request is ${JSON.stringify(request)}`);
  if (!request) {
    throw new CLIError('CRITICAL', 'No authenticated request was recorded');
  }
  let accessToken: unknown = null;
  let dpopToken: unknown = null;
  for (const h of Object.keys(request.headers)) {
    switch (h.toLowerCase()) {
      case 'dpop':
        if (dpopToken) {
          throw new CLIError('CRITICAL', 'Multiple dpop headers found');
        }
        dpopToken = parseJwtComplete(request.headers[h]);
        log('INFO', `dpop: ${JSON.stringify(dpopToken)}`);
        break;
      case 'authorization':
        if (accessToken) {
          throw new CLIError('CRITICAL', 'Multiple authorization headers found');
        }
        accessToken = parseJwt(request.headers[h].split(' ')[1]);
        log('INFO', `Access Token: ${JSON.stringify(accessToken)}`);
        break;
    }
  }
  if (!accessToken) {
    throw new CLIError('CRITICAL', 'No access_token found');
  }
  if (!dpopEnabled) {
    return;
  }
  const cnf = typeof accessToken === 'object' && 'cnf' in accessToken ? accessToken.cnf : undefined;
  const hasJkt = typeof cnf === 'object' && cnf !== null && 'jkt' in cnf && Boolean(cnf.jkt);
  if (!hasJkt) {
    // A missing cnf.jkt means token binding silently didn't take effect.
    throw new CLIError(
      'CRITICAL',
      'DPoP requested but the access token is not bound (missing cnf.jkt)'
    );
  }
  if (!dpopToken) {
    throw new CLIError('CRITICAL', 'DPoP requested but no DPoP proof was sent');
  }
}
