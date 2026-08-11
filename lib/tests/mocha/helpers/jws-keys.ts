import { exportPublicKeyPem } from '../../../tdf3/src/crypto/core/key-format.js';
import { wrapPrivateKey, wrapPublicKey } from '../../../tdf3/src/crypto/core/keys.js';
import { generateSigningKeyPair } from '../../../tdf3/src/crypto/core/rsa.js';
import type {
  ECCurve,
  EcKeyAlgorithm,
  EcSigningAlgorithm,
  KeyPair,
} from '../../../tdf3/src/crypto/declarations.js';

/**
 * Shared signing-key fixtures for the JWS suites (dpop-proof, reqsignature-jws,
 * assertions).
 *
 * Each fixture returns an SDK-opaque `KeyPair` alongside its SPKI PEM, so tests
 * can hand the PEM to `jose.importSPKI` and verify the SDK's output with an
 * independent, RFC-conformant implementation.
 */

export const CURVES: Array<{ namedCurve: ECCurve; alg: EcSigningAlgorithm }> = [
  { namedCurve: 'P-256', alg: 'ES256' },
  { namedCurve: 'P-384', alg: 'ES384' },
  { namedCurve: 'P-521', alg: 'ES512' },
];

export type TestKeyPair = { sdk: KeyPair; pubPem: string };

const CURVE_ALGORITHMS: Record<ECCurve, EcKeyAlgorithm> = {
  'P-256': 'ec:secp256r1',
  'P-384': 'ec:secp384r1',
  'P-521': 'ec:secp521r1',
};

async function withPem(sdk: KeyPair): Promise<TestKeyPair> {
  return { sdk, pubPem: await exportPublicKeyPem(sdk.publicKey) };
}

/**
 * Generated with raw WebCrypto rather than `generateECKeyPair`, which produces
 * ECDH `deriveBits` keys that cannot sign.
 */
export async function ecdsaKeyPair(namedCurve: ECCurve): Promise<TestKeyPair> {
  const algorithm = CURVE_ALGORITHMS[namedCurve];
  const raw = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, [
    'sign',
    'verify',
  ]);
  return withPem({
    publicKey: wrapPublicKey(raw.publicKey, algorithm),
    privateKey: wrapPrivateKey(raw.privateKey, algorithm),
  });
}

/**
 * RS256 is the default DPoP alg for any RSA key and, unlike ES*, its signature
 * is passed through unconverted (no DER<->P1363 transform). Suites use this to
 * exercise that pass-through branch against the same conformant verifier.
 */
export async function rsaKeyPair(): Promise<TestKeyPair> {
  return withPem(await generateSigningKeyPair());
}
