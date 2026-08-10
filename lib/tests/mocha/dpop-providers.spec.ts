import { expect } from 'chai';
import * as jose from 'jose';

import type { AccessToken } from '../../src/auth/oidc.js';
import {
  clientSecretAuthProvider,
  externalAuthProvider,
  refreshAuthProvider,
} from '../../src/auth/providers.js';
import { generateSigningKeyPair } from '../../tdf3/src/crypto/index.js';
import type { KeyPair } from '../../tdf3/src/crypto/declarations.js';

const ORIGIN = 'https://idp.example.test';
const TOKEN_URL = `${ORIGIN}/protocol/openid-connect/token`;

type DPoPOptions = { dpopEnabled?: boolean; signingKey?: KeyPair };

/** The three provider factories, each reduced to "build me one with these DPoP options". */
const FACTORIES: [string, (dpop: DPoPOptions) => Promise<{ oidcAuth: AccessToken }>][] = [
  [
    'clientSecretAuthProvider',
    (dpop) =>
      clientSecretAuthProvider({
        exchange: 'client',
        clientId: 'test-client',
        clientSecret: 'test-secret',
        oidcOrigin: ORIGIN,
        ...dpop,
      }),
  ],
  [
    'externalAuthProvider',
    (dpop) =>
      externalAuthProvider({
        exchange: 'external',
        clientId: 'test-client',
        externalJwt: 'external.jwt.value',
        oidcOrigin: ORIGIN,
        ...dpop,
      }),
  ],
  [
    'refreshAuthProvider',
    (dpop) =>
      refreshAuthProvider({
        exchange: 'refresh',
        clientId: 'test-client',
        refreshToken: 'refresh-token-value',
        oidcOrigin: ORIGIN,
        ...dpop,
      }),
  ],
];

/** Stub the provider's token request and return the headers of the token POST it makes. */
async function tokenPostHeaders(oidcAuth: AccessToken): Promise<Record<string, string>> {
  let sent: Record<string, string> | undefined;
  oidcAuth.request = (_input, init) => {
    sent = init?.headers as Record<string, string>;
    return Promise.resolve(
      new Response(JSON.stringify({ access_token: 'issued-token' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
  };
  expect(await oidcAuth.get(false)).to.equal('issued-token');
  expect(sent, 'no token request was made').to.not.be.undefined;
  return sent!;
}

/**
 * The provider factories must hand `dpopEnabled` and `signingKey` through to the
 * `AccessToken` they build. They used to drop both, so a CLI started with
 * `--dpop` sent its very first POST /token without a DPoP proof, and a
 * DPoP-bound Keycloak client rejected it.
 */
describe('auth provider factories — DPoP passthrough', function (this: Mocha.Suite) {
  this.timeout(10_000);

  let keyPair: KeyPair;

  before(async () => {
    keyPair = await generateSigningKeyPair();
  });

  for (const [name, factory] of FACTORIES) {
    it(`${name} sends a DPoP proof on the token request when given a signing key`, async () => {
      const provider = await factory({ dpopEnabled: true, signingKey: keyPair });
      expect(provider.oidcAuth.config.dpopEnabled).to.equal(true);

      const headers = await tokenPostHeaders(provider.oidcAuth);
      expect(headers).to.have.property('DPoP');
      expect(headers).to.have.property('X-VirtruPubKey');

      const proofHeader = jose.decodeProtectedHeader(headers.DPoP);
      expect(proofHeader.typ).to.equal('dpop+jwt');
      const claims = jose.decodeJwt(headers.DPoP);
      expect(claims.htm).to.equal('POST');
      expect(claims.htu).to.equal(TOKEN_URL);
    });

    it(`${name} sends no DPoP proof when DPoP is not configured`, async () => {
      const provider = await factory({});
      const headers = await tokenPostHeaders(provider.oidcAuth);
      expect(headers).to.not.have.property('DPoP');
      expect(headers).to.not.have.property('X-VirtruPubKey');
    });
  }
});
