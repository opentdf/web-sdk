import { expect } from 'chai';

import { MlKemWrapped } from '../../../tdf3/src/models/key-access.js';
import { Policy } from '../../../tdf3/src/models/policy.js';
import { base64 } from '../../../src/encodings/index.js';
import { ConfigurationError } from '../../../src/errors.js';
import type { CryptoService, PublicKey } from '../../../tdf3/src/crypto/declarations.js';
import { Binary } from '../../../tdf3/src/binary.js';
import { importSymmetricKey } from '../../../tdf3/src/crypto/index.js';
import { decodeKemEnvelopeDer } from '../../../tdf3/src/crypto/core/mlkem-asn1.js';

// ML-KEM-768 ciphertext length, per FIPS 203.
const MLKEM768_CT_LEN = 1088;

// Minimal CryptoService stub covering only what MlKemWrapped.write() touches:
// ML-KEM encapsulation, AES-GCM wrap of the DEK, and the policy-binding HMAC.
// (No HKDF/digest: ML-KEM uses the raw shared secret directly as the AES key.)
const mockCryptoService: CryptoService = {
  async importPublicKey(): Promise<PublicKey> {
    return { _brand: 'PublicKey', algorithm: 'mlkem:768', mlKemLevel: 768 };
  },
  async mlKemEncapsulate() {
    return {
      ciphertext: new Uint8Array(MLKEM768_CT_LEN),
      sharedSecret: await importSymmetricKey(new Uint8Array(32)),
    };
  },
  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(length);
  },
  async encrypt() {
    return {
      payload: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
      authTag: Binary.fromArrayBuffer(new Uint8Array(16).buffer),
    };
  },
  async hmac(): Promise<Uint8Array> {
    return new Uint8Array(32);
  },
} as unknown as CryptoService;

// Compile-time proof that ML-KEM support is an OPTIONAL CryptoService capability:
// `undefined` is assignable to the member type only when it is declared optional.
// If these become required again, assigning `true` to a `false` type fails the build.
const _mlKemEncapsulateIsOptional: undefined extends CryptoService['mlKemEncapsulate']
  ? true
  : false = true;
const _mlKemDecapsulateIsOptional: undefined extends CryptoService['mlKemDecapsulate']
  ? true
  : false = true;
const _generateMlKemKeyPairIsOptional: undefined extends CryptoService['generateMlKemKeyPair']
  ? true
  : false = true;
void _mlKemEncapsulateIsOptional;
void _mlKemDecapsulateIsOptional;
void _generateMlKemKeyPairIsOptional;

describe('MlKemWrapped', () => {
  const url = 'https://example.com';
  const kid = 'test-kid';
  const publicKey = 'test-public-key';
  const metadata = { key: 'value' };
  const sid = 'test-sid';
  const alg = 'mlkem:768' as const;
  const policy: Policy = { uuid: 'test-policy' };
  const encryptedMetadataStr = 'encrypted-metadata';

  it("initializes with type 'mlkem-wrapped' and level from alg", () => {
    const mlKemWrapped = new MlKemWrapped(
      url,
      kid,
      publicKey,
      metadata,
      mockCryptoService,
      sid,
      alg
    );
    expect(mlKemWrapped.type).to.equal('mlkem-wrapped');
    expect(mlKemWrapped.level).to.equal(768);
  });

  it("writes a KeyAccessObject with type 'mlkem-wrapped'", async () => {
    const mlKemWrapped = new MlKemWrapped(
      url,
      kid,
      publicKey,
      metadata,
      mockCryptoService,
      sid,
      alg
    );

    const dek = await importSymmetricKey(new Uint8Array([1, 2, 3, 4, 5]));
    const kao = await mlKemWrapped.write(policy, dek, encryptedMetadataStr);

    expect(kao).to.have.property('type', 'mlkem-wrapped');
    expect(kao).to.have.property('url', url);
    expect(kao).to.have.property('protocol', 'kas');
    expect(kao).to.have.property('wrappedKey');
    expect(kao).to.have.property('encryptedMetadata', base64.encode(encryptedMetadataStr));
    expect(kao).to.have.property('kid', kid);
    expect(kao).to.have.property('sid', sid);
    expect(kao.policyBinding).to.have.property('alg', 'HS256');

    // wrappedKey is a DER kemEnvelope { [0] kemCiphertext, [1] encryptedDek }
    // where encryptedDek = nonce(12) || aes-256-gcm ct || tag(16).
    const { kemCiphertext, encryptedDek } = decodeKemEnvelopeDer(
      new Uint8Array(base64.decodeArrayBuffer(kao.wrappedKey!))
    );
    expect(kemCiphertext.length).to.equal(MLKEM768_CT_LEN);
    expect(encryptedDek.length).to.equal(12 + 16 + 16);
  });

  it('requires a non-empty kid', () => {
    expect(
      () => new MlKemWrapped(url, '', publicKey, metadata, mockCryptoService, sid, alg)
    ).to.throw(ConfigurationError);
  });

  it('write() throws ConfigurationError when the CryptoService lacks ML-KEM support', async () => {
    // A custom (e.g. HSM-backed) service that predates post-quantum support: it
    // implements importPublicKey but omits the optional ML-KEM methods entirely.
    const noMlKemService: CryptoService = {
      async importPublicKey(): Promise<PublicKey> {
        return { _brand: 'PublicKey', algorithm: 'mlkem:768', mlKemLevel: 768 };
      },
    } as unknown as CryptoService;

    const mlKemWrapped = new MlKemWrapped(url, kid, publicKey, metadata, noMlKemService, sid, alg);
    const dek = await importSymmetricKey(new Uint8Array([1, 2, 3, 4, 5]));

    let err: unknown;
    try {
      await mlKemWrapped.write(policy, dek, encryptedMetadataStr);
    } catch (e) {
      err = e;
    }
    expect(err).to.be.instanceOf(ConfigurationError);
  });
});
