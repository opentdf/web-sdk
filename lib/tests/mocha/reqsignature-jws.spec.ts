import { expect } from 'chai';
import * as jose from 'jose';

import { reqSignature } from '../../src/auth/auth.js';
import { signJwt, verifyJwt } from '../../tdf3/src/crypto/jwt.js';
import { DefaultCryptoService } from '../../tdf3/src/crypto/index.js';
import {
  CURVES,
  decodeBase64url,
  ecdsaKeyPair,
  encodeBase64url,
  rsaKeyPair,
} from './helpers/jws-keys.js';

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

  it('reqSignature RS256 token verifies against jose.jwtVerify', async () => {
    const { sdk, pubPem } = await rsaKeyPair();

    const token = await reqSignature(
      { requestBody: 'hello' },
      sdk.privateKey,
      DefaultCryptoService,
      {
        alg: 'RS256',
      }
    );

    const key = await jose.importSPKI(pubPem, 'RS256');
    const { payload } = await jose.jwtVerify(token, key);
    expect(payload.requestBody).to.equal('hello');
    expect(payload.iat).to.be.a('number');
    expect(payload.exp).to.be.a('number');
  });

  it('signJwt RS256 round-trips through verifyJwt', async () => {
    const { sdk } = await rsaKeyPair();
    const token = await signJwt(DefaultCryptoService, { sub: 'test' }, sdk.privateKey, {
      alg: 'RS256',
    });
    const { payload } = await verifyJwt(DefaultCryptoService, token, sdk.publicKey, {
      algorithms: ['RS256'],
    });
    expect(payload.sub).to.equal('test');
  });

  it('verifyJwt rejects a truncated ES256 signature', async () => {
    const { sdk } = await ecdsaKeyPair('P-256');
    const token = await signJwt(DefaultCryptoService, { sub: 'test' }, sdk.privateKey, {
      alg: 'ES256',
    });
    const [header, payload, signature] = token.split('.');
    const truncated = encodeBase64url(decodeBase64url(signature).subarray(1));

    let caught: unknown;
    try {
      await verifyJwt(DefaultCryptoService, `${header}.${payload}.${truncated}`, sdk.publicKey, {
        algorithms: ['ES256'],
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).to.be.instanceOf(Error);
    expect((caught as Error).message).to.include(
      'Invalid IEEE P1363 signature: expected 64 bytes for ES256, got 63'
    );
  });
});
