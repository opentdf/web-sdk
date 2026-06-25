import { expect } from 'chai';
import * as jose from 'jose';

import { reqSignature } from '../../src/auth/auth.js';
import { signJwt, verifyJwt } from '../../tdf3/src/crypto/jwt.js';
import { DefaultCryptoService } from '../../tdf3/src/crypto/index.js';
import { importPrivateKey, importPublicKey } from '../../tdf3/src/crypto/core/key-format.js';
import type { KeyPair } from '../../tdf3/src/crypto/declarations.js';

/**
 * RFC 7518 §3.4 conformance for `signJwt`/`reqSignature` (the KAS rewrap request
 * token signer).
 *
 * Regression for DSPX-3397: the rewrap request token was signed with ECDSA
 * signatures in DER form, which a real (RFC-conformant) KAS rejects with
 * "unable to verify request token". The mock test server only `decodeJwt`s the
 * token (no signature check), so the in-SDK round-trip and the mock both passed
 * while the real platform failed. Verifying against `jose.jwtVerify` — which
 * requires raw IEEE P1363 (R||S) signatures — catches the DER-vs-raw bug.
 */

const CURVES: Array<{ namedCurve: 'P-256' | 'P-384' | 'P-521'; alg: 'ES256' | 'ES384' | 'ES512' }> =
  [
    { namedCurve: 'P-256', alg: 'ES256' },
    { namedCurve: 'P-384', alg: 'ES384' },
    { namedCurve: 'P-521', alg: 'ES512' },
  ];

function derToPem(der: Uint8Array, label: string): string {
  let b = '';
  for (let i = 0; i < der.length; i++) b += String.fromCharCode(der[i]);
  const b64 =
    btoa(b)
      .match(/.{1,64}/g)
      ?.join('\n') ?? btoa(b);
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
}

async function ecdsaKeyPair(
  namedCurve: 'P-256' | 'P-384' | 'P-521'
): Promise<{ sdk: KeyPair; pubPem: string }> {
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
  return { sdk: { publicKey, privateKey }, pubPem };
}

describe('reqSignature / signJwt — JWS conformance vs jose.jwtVerify (RFC 7518 §3.4)', function (this: Mocha.Suite) {
  this.timeout(10_000);

  for (const { namedCurve, alg } of CURVES) {
    it(`reqSignature ${alg} token verifies against jose.jwtVerify`, async () => {
      const { sdk, pubPem } = await ecdsaKeyPair(namedCurve);

      const token = await reqSignature(
        { requestBody: 'hello' },
        sdk.privateKey,
        DefaultCryptoService,
        {
          alg,
        }
      );

      // jose requires raw IEEE P1363 signatures — this rejects DER.
      const key = await jose.importSPKI(pubPem, alg);
      const { payload } = await jose.jwtVerify(token, key);
      expect(payload.requestBody).to.equal('hello');
      expect(payload.iat).to.be.a('number');
      expect(payload.exp).to.be.a('number');
    });

    it(`signJwt ${alg} round-trips through verifyJwt`, async () => {
      const { sdk } = await ecdsaKeyPair(namedCurve);
      const token = await signJwt(DefaultCryptoService, { sub: 'test' }, sdk.privateKey, { alg });
      const { payload } = await verifyJwt(DefaultCryptoService, token, sdk.publicKey, {
        algorithms: [alg],
      });
      expect(payload.sub).to.equal('test');
    });
  }
});
