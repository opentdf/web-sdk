import { importPrivateKey, importPublicKey } from '../../../tdf3/src/crypto/core/key-format.js';
import type { KeyPair } from '../../../tdf3/src/crypto/declarations.js';

/**
 * Shared key fixtures for the JWS conformance suites (dpop-proof, reqsignature-jws).
 *
 * Both suites need SDK-opaque KeyPairs generated the way real callers get them:
 * raw WebCrypto keygen, exported to DER, wrapped as PEM, then imported through
 * the SDK's key-format layer (the same dance `cli/src/dpop-helpers.ts` does).
 * The PEM is returned alongside so tests can hand it to `jose.importSPKI` for
 * independent verification.
 */

export type NamedCurve = 'P-256' | 'P-384' | 'P-521';
export type EcdsaAlg = 'ES256' | 'ES384' | 'ES512';

export const CURVES: Array<{ namedCurve: NamedCurve; alg: EcdsaAlg }> = [
  { namedCurve: 'P-256', alg: 'ES256' },
  { namedCurve: 'P-384', alg: 'ES384' },
  { namedCurve: 'P-521', alg: 'ES512' },
];

export type PemKeyPair = { sdk: KeyPair; pubPem: string };

export function derToPem(der: Uint8Array, label: string): string {
  let b = '';
  for (let i = 0; i < der.length; i++) b += String.fromCharCode(der[i]);
  const b64 =
    btoa(b)
      .match(/.{1,64}/g)
      ?.join('\n') ?? btoa(b);
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
}

export function decodeBase64url(value: string): Uint8Array {
  const base64 = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

export function encodeBase64url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function toSdkKeyPair(raw: CryptoKeyPair): Promise<PemKeyPair> {
  const [privDer, pubDer] = await Promise.all([
    crypto.subtle.exportKey('pkcs8', raw.privateKey),
    crypto.subtle.exportKey('spki', raw.publicKey),
  ]);
  const privPem = derToPem(new Uint8Array(privDer), 'PRIVATE KEY');
  const pubPem = derToPem(new Uint8Array(pubDer), 'PUBLIC KEY');
  const [privateKey, publicKey] = await Promise.all([
    importPrivateKey(privPem, { usage: 'sign', extractable: true }),
    importPublicKey(pubPem, { usage: 'sign', extractable: true }),
  ]);
  return { sdk: { publicKey, privateKey }, pubPem };
}

export async function ecdsaKeyPair(namedCurve: NamedCurve): Promise<PemKeyPair> {
  const raw = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, [
    'sign',
    'verify',
  ]);
  return toSdkKeyPair(raw);
}

/**
 * RS256 is the default DPoP alg for any RSA key and, unlike ES*, its signature
 * is passed through unconverted (no DER<->P1363 transform). Suites use this to
 * exercise that pass-through branch against the same conformant verifier.
 */
export async function rsaKeyPair(): Promise<PemKeyPair> {
  const raw = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );
  return toSdkKeyPair(raw);
}
