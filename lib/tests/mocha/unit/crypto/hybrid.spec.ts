import { expect } from 'chai';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

import { isPublicKeyAlgorithm, publicKeyAlgorithmToJwa } from '../../../../src/access.js';
import { base64, hex } from '../../../../src/encodings/index.js';
import { removePemFormatting } from '../../../../tdf3/src/crypto/crypto-utils.js';
import { readTlv } from '../../../../tdf3/src/crypto/core/asn1.js';
import { hybridCombiner, hybridEncapsulate } from '../../../../tdf3/src/crypto/core/hybrid.js';
import {
  decodeHybridSpkiDer,
  encodeHybridSpkiDer,
  HYBRID_PARAMETERS,
} from '../../../../tdf3/src/crypto/core/hybrid-asn1.js';
import {
  exportPublicKeyPem,
  importPublicKey,
  parsePublicKeyPem,
} from '../../../../tdf3/src/crypto/core/key-format.js';
import { unwrapSymmetricKey } from '../../../../tdf3/src/crypto/core/keys.js';
import { decodeKemEnvelopeDer } from '../../../../tdf3/src/crypto/core/mlkem-asn1.js';
import type { HybridKeyAlgorithm } from '../../../../tdf3/src/crypto/declarations.js';
import { DefaultCryptoService, importSymmetricKey } from '../../../../tdf3/src/crypto/index.js';
import { HybridWrapped } from '../../../../tdf3/src/models/key-access.js';
import type { Policy } from '../../../../tdf3/src/models/policy.js';
import {
  P256_MLKEM768_PRIVATE_KEY,
  P256_MLKEM768_PUBLIC_KEY,
  P384_MLKEM1024_PRIVATE_KEY,
  P384_MLKEM1024_PUBLIC_KEY,
} from './hybrid-fixtures.js';

const FIXTURES: Record<HybridKeyAlgorithm, { publicKey: string; privateKey: string }> = {
  'hpqt:secp256r1-mlkem768': {
    publicKey: P256_MLKEM768_PUBLIC_KEY,
    privateKey: P256_MLKEM768_PRIVATE_KEY,
  },
  'hpqt:secp384r1-mlkem1024': {
    publicKey: P384_MLKEM1024_PUBLIC_KEY,
    privateKey: P384_MLKEM1024_PRIVATE_KEY,
  },
};

const MLKEM = { 768: ml_kem768, 1024: ml_kem1024 } as const;

const fromHex = (text: string): Uint8Array => new Uint8Array(hex.decodeArrayBuffer(text));
const toHex = (bytes: Uint8Array): string => hex.encodeArrayBuffer(bytes.slice().buffer);

const ID_EC_PUBLIC_KEY = Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
const CURVE_OIDS = {
  'P-256': Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07),
  'P-384': Uint8Array.of(0x2b, 0x81, 0x04, 0x00, 0x22),
} as const;

function tlv(tag: number, content: Uint8Array): Uint8Array {
  const length =
    content.length < 0x80
      ? Uint8Array.of(content.length)
      : content.length < 0x100
        ? Uint8Array.of(0x81, content.length)
        : Uint8Array.of(0x82, content.length >> 8, content.length & 0xff);
  return Uint8Array.of(tag, ...length, ...content);
}

/**
 * The KAS side, written from the platform's lib/ocrypto (hybrid_nist.go,
 * decapsulate): the PKCS#8 private key holds the 64-byte ML-KEM seed followed
 * by an RFC 5915 ECPrivateKey.
 */
async function decapsulate(
  algorithm: HybridKeyAlgorithm,
  privateKeyPem: string,
  kasPublicKeyPem: string,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const params = HYBRID_PARAMETERS[algorithm];
  const pkcs8 = new Uint8Array(base64.decodeArrayBuffer(removePemFormatting(privateKeyPem)));
  const outer = readTlv(pkcs8, 0);
  const version = readTlv(pkcs8, outer.contentStart);
  const algorithmIdentifier = readTlv(pkcs8, version.next);
  const privateKey = readTlv(pkcs8, algorithmIdentifier.next);
  const raw = pkcs8.subarray(privateKey.contentStart, privateKey.contentEnd);
  const seed = raw.subarray(0, 64);
  const ecPrivateKey = raw.subarray(64);

  const mlkemCT = ciphertext.slice(0, params.mlKemCiphertextSize);
  const tradCT = ciphertext.slice(params.mlKemCiphertextSize);
  const { secretKey } = MLKEM[params.mlKemLevel].keygen(seed);
  const mlkemSS = MLKEM[params.mlKemLevel].decapsulate(mlkemCT, secretKey);

  // WebCrypto imports an EC private key as PKCS#8 only.
  const ecPkcs8 = tlv(
    0x30,
    Uint8Array.of(
      ...tlv(0x02, Uint8Array.of(0)),
      ...tlv(
        0x30,
        Uint8Array.of(...tlv(0x06, ID_EC_PUBLIC_KEY), ...tlv(0x06, CURVE_OIDS[params.curve]))
      ),
      ...tlv(0x04, ecPrivateKey)
    )
  );
  const curve = { name: 'ECDH', namedCurve: params.curve };
  const kasEcKey = await crypto.subtle.importKey('pkcs8', ecPkcs8.slice(), curve, false, [
    'deriveBits',
  ]);
  const ephemeral = await crypto.subtle.importKey('raw', tradCT, curve, false, []);
  const tradSS = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephemeral },
      kasEcKey,
      ((params.ecPointSize - 1) / 2) * 8
    )
  );
  const kasRaw = decodeHybridSpkiDer(
    new Uint8Array(base64.decodeArrayBuffer(removePemFormatting(kasPublicKeyPem)))
  ).rawKey;
  const tradPK = kasRaw.subarray(params.mlKemPublicKeySize);
  return hybridCombiner(params, mlkemSS, tradSS, tradCT, tradPK);
}

describe('hybrid ML-KEM + ECDH (hpqt:*)', () => {
  // Known-answer tests of draft-ietf-lamps-pq-composite-kem-14, which the
  // platform's lib/ocrypto also checks (hybrid_conformance_test.go).
  it('combines as draft-ietf-lamps-pq-composite-kem-14 §3.4 specifies', () => {
    const p256 = hybridCombiner(
      HYBRID_PARAMETERS['hpqt:secp256r1-mlkem768'],
      fromHex('ca48920ded22e063f98a79a4091508678b7042cab63f78c571ff392e82612d43'),
      fromHex('ef1c92443aaf987000e3470d34332b4c53ff0cdd4554b6bf377bf7bdb677d3d0'),
      fromHex(
        '041d155f6d3078d7e2cd4f9f758947029795dd9ab6d6e92d81d19171270cdefcd4' +
          'abb682edbb22faf961ce75fc688109931bfa24468f646b97eca4d57d5f5e7610'
      ),
      fromHex(
        '04ba2bfbf7b91182eb1fad54a2940c8b1dfd53de55fa3c02d199a3159ff73d38d2' +
          '9aa94f32e3e82bcc99b165320297149455997d7c3ea5ac97cd987d3e80396a3e'
      )
    );
    expect(toHex(p256)).to.equal(
      'd6c69aa6e986b620a2777d8cf1fb6be1b2255d6efae0566deb34c882b38846ee'
    );

    const p384 = hybridCombiner(
      HYBRID_PARAMETERS['hpqt:secp384r1-mlkem1024'],
      fromHex('c0f87f0c53fa8e2ba192a494694d37d1e3cf99c65e0dc5f69b2cc044b3fb205d'),
      fromHex(
        '4d52b7ef430382f479603207c0b8f7aa5bc35d8758835007e39a2642ad65e635' +
          'd674db7a5513889657fb24e4e228a098'
      ),
      fromHex(
        '0401a5b81dcb51290a0eb142b9032d5a37503164b7a20ac0e3b52dc54f9b0b7c9f' +
          'dd2699a59563a0b9ad0e54478846faeab72b92275e1fbb8b963bcc6e80e30c089' +
          'fbe4ed8d47ec76951db94aede46e679d5692eeb1d1b150d5b2e6660dc67c469'
      ),
      fromHex(
        '0468cc4acc5dd85edbcbf25bae7ee7dcacec2968ea7ee57fc91311cb9c47d4a24c' +
          '3854e5ce3e5d0b309fda493224520f2870496eb16571108b3deafd72c1df17edc' +
          '302fbb8b60bae44d93177e6df5278e4667a090a2d59a2076f41d693975e8d19'
      )
    );
    expect(toHex(p384)).to.equal(
      'eb60f6c80a309ad4158d7b02f2cf8c947faead96ebbd85c3f62a94868ffddca4'
    );
  });

  it('is a public key algorithm, named by its composite label', () => {
    expect(isPublicKeyAlgorithm('hpqt:secp256r1-mlkem768')).to.be.true;
    expect(isPublicKeyAlgorithm('hpqt:secp384r1-mlkem1024')).to.be.true;
    expect(publicKeyAlgorithmToJwa('hpqt:secp256r1-mlkem768')).to.equal('MLKEM768-P256');
    expect(publicKeyAlgorithmToJwa('hpqt:secp384r1-mlkem1024')).to.equal('MLKEM1024-P384');
  });

  for (const algorithm of Object.keys(FIXTURES) as HybridKeyAlgorithm[]) {
    describe(algorithm, () => {
      const { publicKey, privateKey } = FIXTURES[algorithm];
      const params = HYBRID_PARAMETERS[algorithm];

      it('reads the public keys the platform writes, and writes them back unchanged', async () => {
        expect((await parsePublicKeyPem(publicKey)).algorithm).to.equal(algorithm);
        const key = await importPublicKey(publicKey, {});
        expect(key.algorithm).to.equal(algorithm);
        expect(removePemFormatting(await exportPublicKeyPem(key))).to.equal(
          removePemFormatting(publicKey)
        );
      });

      it('encodes and decodes the composite SPKI', () => {
        const raw = new Uint8Array(params.mlKemPublicKeySize + params.ecPointSize).fill(7);
        expect(decodeHybridSpkiDer(encodeHybridSpkiDer(raw, algorithm))).to.deep.equal({
          algorithm,
          rawKey: raw,
        });
      });

      it('encapsulates to a key that the platform decapsulates with its private key', async () => {
        const key = await importPublicKey(publicKey, {});
        const { ciphertext, sharedSecret } = await hybridEncapsulate(key);

        expect(ciphertext.length).to.equal(params.mlKemCiphertextSize + params.ecPointSize);
        expect(ciphertext[params.mlKemCiphertextSize]).to.equal(0x04);
        const recovered = await decapsulate(algorithm, privateKey, publicKey, ciphertext);
        expect(toHex(recovered)).to.equal(toHex(unwrapSymmetricKey(sharedSecret)));
      });

      it("writes a 'hybrid-wrapped' key access object whose key the KAS can unwrap", async () => {
        const dek = await importSymmetricKey(new Uint8Array(32).fill(3));
        const policy: Policy = { uuid: 'test-policy' };
        const wrapped = new HybridWrapped(
          'https://kas.example/kas',
          'h1',
          publicKey,
          undefined,
          DefaultCryptoService,
          undefined,
          algorithm
        );

        const kao = await wrapped.write(policy, dek, 'encrypted-metadata');

        expect(kao.type).to.equal('hybrid-wrapped');
        expect(kao.kid).to.equal('h1');
        const envelope = decodeKemEnvelopeDer(
          new Uint8Array(base64.decodeArrayBuffer(kao.wrappedKey ?? ''))
        );
        expect(envelope.kemCiphertext.length).to.equal(
          params.mlKemCiphertextSize + params.ecPointSize
        );
        // encryptedDek = nonce(12) || AES-GCM(DEK) || tag(16)
        expect(envelope.encryptedDek.length).to.equal(12 + 32 + 16);
        const wrapKey = await decapsulate(algorithm, privateKey, publicKey, envelope.kemCiphertext);
        const aes = await crypto.subtle.importKey('raw', wrapKey.slice(), 'AES-GCM', false, [
          'decrypt',
        ]);
        const dekBytes = new Uint8Array(
          await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: envelope.encryptedDek.slice(0, 12) },
            aes,
            envelope.encryptedDek.slice(12)
          )
        );
        expect([...dekBytes]).to.deep.equal(new Array(32).fill(3));
      });

      it('refuses to wrap without a key id, which the KAS needs to find its key', () => {
        expect(
          () =>
            new HybridWrapped(
              'https://kas.example/kas',
              ' ',
              publicKey,
              undefined,
              DefaultCryptoService,
              undefined,
              algorithm
            )
        ).to.throw('HybridWrapped requires a non-empty kid');
      });
    });
  }
});
