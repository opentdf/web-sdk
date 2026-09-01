import { expect } from 'chai';
import * as jose from 'jose';

import dpopFn from '../../src/auth/dpop.js';
import { DefaultCryptoService } from '../../tdf3/src/crypto/index.js';
import { importPrivateKey, importPublicKey } from '../../tdf3/src/crypto/core/key-format.js';
import type { KeyPair } from '../../tdf3/src/crypto/declarations.js';

/**
 * End-to-end DPoP proof signing tests.
 *
 * These tests verify the proofs minted by `dpopFn` (the function called from
 * `AccessToken.doPost` and `withCreds`) against an independent, RFC 9449 /
 * RFC 7518 §3.4 conformant verifier (`jose.jwtVerify`).
 *
 * Why these tests exist: the SDK's internal sign/verify pair is symmetric
 * (both encode/decode ECDSA signatures as DER), so it round-trips inside this
 * SDK even when the wire format is non-conformant. `jose.jwtVerify` is the
 * same library used by real Keycloak under the hood — feeding our proofs
 * through it catches DER-vs-raw and similar bugs that the in-SDK round-trip
 * cannot. The earlier DSPX-3397 "Invalid token signature" failure from
 * Keycloak would have been caught locally by these tests.
 */

const HTU = 'https://example.test/protocol/openid-connect/token';
const HTM = 'POST';

async function ecdsaKeyPair(namedCurve: 'P-256' | 'P-384' | 'P-521'): Promise<KeyPair> {
  // Generate via raw WebCrypto, then round-trip through PEM to obtain the
  // SDK's opaque PrivateKey/PublicKey types (the same dance the CLI does in
  // `cli/src/dpop-helpers.ts`). Keeps the test aligned with what real DPoP
  // callers feed `dpopFn`.
  const raw = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, [
    'sign',
    'verify',
  ]);
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
  return { publicKey, privateKey };
}

async function rsaKeyPair(): Promise<KeyPair> {
  // RS256 is the default DPoP alg for any RSA key and, unlike ES*, its signature
  // is passed through unconverted (no DER↔P1363 transform). Exercise that branch
  // against the same conformant verifier the ES cases use.
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
  return { publicKey, privateKey };
}

function derToPem(der: Uint8Array, label: string): string {
  let b = '';
  for (let i = 0; i < der.length; i++) b += String.fromCharCode(der[i]);
  const b64 =
    btoa(b)
      .match(/.{1,64}/g)
      ?.join('\n') ?? btoa(b);
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
}

const CURVES: Array<{ namedCurve: 'P-256' | 'P-384' | 'P-521'; alg: 'ES256' | 'ES384' | 'ES512' }> =
  [
    { namedCurve: 'P-256', alg: 'ES256' },
    { namedCurve: 'P-384', alg: 'ES384' },
    { namedCurve: 'P-521', alg: 'ES512' },
  ];

describe('DPoP proof — JWS conformance vs jose.jwtVerify (RFC 9449 + RFC 7518 §3.4)', function (this: Mocha.Suite) {
  this.timeout(10_000);

  for (const { namedCurve, alg } of CURVES) {
    it(`${alg} proof verifies against jose.jwtVerify`, async () => {
      const kp = await ecdsaKeyPair(namedCurve);
      const proof = await dpopFn(kp, DefaultCryptoService, HTU, HTM);

      // Verify with the public key extracted from the proof's own header, the
      // way a real DPoP-aware server (Keycloak) would.
      const header = jose.decodeProtectedHeader(proof);
      expect(header.typ).to.equal('dpop+jwt');
      expect(header.alg).to.equal(alg);
      expect(header.jwk).to.exist;

      const key = await jose.importJWK(header.jwk as jose.JWK, alg);
      const { payload } = await jose.jwtVerify(proof, key);
      expect(payload.htu).to.equal(HTU);
      expect(payload.htm).to.equal(HTM);
      expect(payload.jti).to.be.a('string').and.have.length.greaterThan(0);
      expect(payload.iat).to.be.a('number');
    });

    it(`${alg} proof verification rejects a flipped signature byte`, async () => {
      const kp = await ecdsaKeyPair(namedCurve);
      const proof = await dpopFn(kp, DefaultCryptoService, HTU, HTM);
      const tampered = flipOneBitInSignatureSegment(proof);

      const header = jose.decodeProtectedHeader(proof);
      const key = await jose.importJWK(header.jwk as jose.JWK, alg);
      let threw = false;
      try {
        await jose.jwtVerify(tampered, key);
      } catch {
        threw = true;
      }
      expect(threw, 'jose.jwtVerify must reject a tampered signature').to.equal(true);
    });

    it(`${alg} proof verification rejects a swapped jwk header (binding intact, key wrong)`, async () => {
      const kp1 = await ecdsaKeyPair(namedCurve);
      const kp2 = await ecdsaKeyPair(namedCurve);

      const proof = await dpopFn(kp1, DefaultCryptoService, HTU, HTM);

      // Build a forged proof: same payload + signature but kp2's public JWK in
      // the header. A correct verifier must reject because the signature was
      // made by kp1.privateKey.
      const [hdrB64, payloadB64, sigB64] = proof.split('.');
      const realHeader = JSON.parse(
        new TextDecoder().decode(jose.base64url.decode(hdrB64))
      ) as jose.ProtectedHeaderParameters;
      const fakeJwk = await crypto.subtle.exportKey(
        'jwk',
        (await jose.importJWK((await proofHeaderJwkFor(kp2, alg)) as jose.JWK, alg)) as CryptoKey
      );
      delete (fakeJwk as Record<string, unknown>).d;
      delete (fakeJwk as Record<string, unknown>).key_ops;
      realHeader.jwk = fakeJwk as jose.JWK;
      const forgedHdrB64 = jose.base64url.encode(
        new TextEncoder().encode(JSON.stringify(realHeader))
      );
      const forged = `${forgedHdrB64}.${payloadB64}.${sigB64}`;

      const key = await jose.importJWK(realHeader.jwk as jose.JWK, alg);
      let threw = false;
      try {
        await jose.jwtVerify(forged, key);
      } catch {
        threw = true;
      }
      expect(threw, 'jose.jwtVerify must reject a forged proof with mismatched jwk').to.equal(true);
    });
  }
});

describe('DPoP proof — RS256 JWS conformance vs jose.jwtVerify (RFC 9449)', function (this: Mocha.Suite) {
  this.timeout(10_000);

  it('RS256 proof verifies against jose.jwtVerify', async () => {
    const kp = await rsaKeyPair();
    const proof = await dpopFn(kp, DefaultCryptoService, HTU, HTM);

    const header = jose.decodeProtectedHeader(proof);
    expect(header.typ).to.equal('dpop+jwt');
    expect(header.alg).to.equal('RS256');
    expect(header.jwk).to.exist;

    const key = await jose.importJWK(header.jwk as jose.JWK, 'RS256');
    const { payload } = await jose.jwtVerify(proof, key);
    expect(payload.htu).to.equal(HTU);
    expect(payload.htm).to.equal(HTM);
    expect(payload.jti).to.be.a('string').and.have.length.greaterThan(0);
    expect(payload.iat).to.be.a('number');
  });

  it('RS256 proof verification rejects a flipped signature byte', async () => {
    const kp = await rsaKeyPair();
    const proof = await dpopFn(kp, DefaultCryptoService, HTU, HTM);
    const tampered = flipOneBitInSignatureSegment(proof);

    const header = jose.decodeProtectedHeader(proof);
    const key = await jose.importJWK(header.jwk as jose.JWK, 'RS256');
    let threw = false;
    try {
      await jose.jwtVerify(tampered, key);
    } catch {
      threw = true;
    }
    expect(threw, 'jose.jwtVerify must reject a tampered RS256 signature').to.equal(true);
  });
});

describe('DPoP proof — unsupported key algorithm', function () {
  it('throws before signing when the key algorithm is not a supported JWS alg', async () => {
    // determineJWSAlgorithmFromKeyInfo (now typed to return only the four
    // AsymmetricSigningAlgorithm values) must still reject an unknown key
    // algorithm string up front, rather than the type change silently widening
    // what flows into the signer.
    const bogusKeyPair = {
      publicKey: { algorithm: 'ec:brainpoolP256r1' },
      privateKey: {},
    } as unknown as KeyPair;

    let err: Error | undefined;
    try {
      await dpopFn(bogusKeyPair, DefaultCryptoService, HTU, HTM);
    } catch (e) {
      err = e as Error;
    }
    expect(err, 'expected an unsupported-algorithm error').to.be.instanceOf(Error);
    expect(err?.message).to.match(/unsupported key algorithm/);
  });
});

/**
 * Mint a real proof solely to extract a clean JWK for the public key.
 * Round-tripping through `dpopFn` ensures the JWK shape matches what the
 * SDK emits in real proofs.
 */
async function proofHeaderJwkFor(kp: KeyPair, alg: 'ES256' | 'ES384' | 'ES512'): Promise<unknown> {
  const proof = await dpopFn(kp, DefaultCryptoService, HTU, HTM);
  const header = jose.decodeProtectedHeader(proof);
  void alg; // alg unused; kept in signature for caller clarity
  return header.jwk;
}

/**
 * Flip exactly one bit of the base64url-decoded signature segment.
 * Re-encodes back into the JWT compact form.
 */
function flipOneBitInSignatureSegment(jwt: string): string {
  const [h, p, s] = jwt.split('.');
  const sig = jose.base64url.decode(s);
  sig[0] ^= 0x01;
  return `${h}.${p}.${jose.base64url.encode(sig)}`;
}
