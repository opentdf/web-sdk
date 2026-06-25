import { assert, expect } from 'chai';

import { getMocks } from '../mocks/index.js';
import { Client } from '../../tdf3/src/index.js';
import { clientSecretAuthProvider } from '../../src/auth/providers.js';
import { globalNonceCache } from '../../src/auth/dpop-nonce.js';
import { generateSigningKeyPair } from '../../tdf3/src/crypto/index.js';
import type { KeyPair } from '../../tdf3/src/crypto/declarations.js';
import type { Scope } from '../../tdf3/src/client/builders.js';

const Mocks = getMocks();

const SERVER_ORIGIN = 'http://localhost:3000';
const TOKEN_URL = `${SERVER_ORIGIN}/protocol/openid-connect/token`;
// Fixed nonce the mock server's resource-server (rewrap) gate demands; see
// DPOP_RS_NONCE in tests/server.ts.
const RS_NONCE = 'dpop-test-rs-nonce-xyz';

/**
 * End-to-end regression for the Connect-RPC DPoP-Nonce challenge retry on the
 * KAS *rewrap* path (RFC 9449 §9) — the exact xtest scenario
 * (`test_dpop_server_issued_nonce_retry`) that failed only when js was the
 * decrypt SDK against a `require_nonce` KAS.
 *
 * Drives a full encrypt → decrypt roundtrip through a DPoP auth provider so the
 * rewrap carries `Authorization: DPoP <token>` and trips the mock server's RS
 * gate. The first proof lacks the RS nonce, the server challenges with a 401 +
 * `DPoP-Nonce`, and `authProviderInterceptor` must cache the nonce, re-sign, and
 * retry once for the rewrap (and therefore the decrypt) to succeed.
 */
describe('DPoP RS nonce retry on the KAS rewrap path — integration with mock server', function (this: Mocha.Suite) {
  this.timeout(10_000);

  let dpopKeyPair: KeyPair;

  before(async () => {
    dpopKeyPair = await generateSigningKeyPair();
  });

  afterEach(() => {
    globalNonceCache.clearAll();
  });

  it('decrypt survives the rewrap nonce challenge and returns the plaintext', async () => {
    const expectedVal = 'rewrap nonce roundtrip';

    // A DPoP-enabled provider makes every authenticated request (token + rewrap)
    // present `Authorization: DPoP` and a proof, which is what activates the RS
    // gate on the mock KAS rewrap endpoint.
    const authProvider = await clientSecretAuthProvider({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      oidcOrigin: SERVER_ORIGIN,
      oidcTokenEndpoint: TOKEN_URL,
      exchange: 'client',
      dpopEnabled: true,
      signingKey: dpopKeyPair,
    });

    const client = new Client.Client({
      kasEndpoint: SERVER_ORIGIN,
      platformUrl: SERVER_ORIGIN,
      allowedKases: [SERVER_ORIGIN],
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'test-client',
      authProvider,
    });

    const scope: Scope = { dissem: ['user@domain.com'], attributes: [] };

    const encryptedStream = await client.encrypt({
      metadata: Mocks.getMetadataObject(),
      offline: true,
      scope,
      source: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(expectedVal));
          controller.close();
        },
      }),
    });

    const decryptStream = await client.decrypt({
      source: { type: 'stream', location: encryptedStream.stream },
    });

    const { value: decryptedText } = await decryptStream.stream.getReader().read();
    assert.equal(new TextDecoder().decode(decryptedText), expectedVal);

    // A successful decrypt proves the rewrap survived the challenge; the cached
    // RS nonce proves a challenge actually happened and the retry adopted it.
    expect(globalNonceCache.get(SERVER_ORIGIN)).to.equal(RS_NONCE);
  });
});
