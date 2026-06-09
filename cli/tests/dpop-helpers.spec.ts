// cli/tests/dpop-helpers.spec.ts
import { expect } from '@esm-bundle/chai';
import {
  derToPem,
  generateEphemeralDPoPKeyPair,
  resolveDPoPKeyPair,
} from '../src/dpop-helpers.js';

describe('derToPem', function () {
  it('wraps DER bytes in PEM armor with the given type', function () {
    const der = new Uint8Array([0x01, 0x02, 0x03]);
    const pem = derToPem(der, 'PUBLIC KEY');
    expect(pem).to.include('-----BEGIN PUBLIC KEY-----');
    expect(pem).to.include('-----END PUBLIC KEY-----');
    expect(pem).to.include('AQID'); // base64 of [1,2,3]
  });

  it('wraps an ArrayBuffer in PEM armor', function () {
    const der = new Uint8Array([0x01, 0x02]).buffer;
    const pem = derToPem(der, 'PRIVATE KEY');
    expect(pem).to.include('-----BEGIN PRIVATE KEY-----');
    expect(pem).to.include('-----END PRIVATE KEY-----');
  });
});

describe('generateEphemeralDPoPKeyPair', function () {
  it('generates ES256 (ec:secp256r1) key pair', async function () {
    const kp = await generateEphemeralDPoPKeyPair('ES256');
    expect(kp.publicKey.algorithm).to.equal('ec:secp256r1');
  });

  it('generates ES384 (ec:secp384r1) key pair', async function () {
    const kp = await generateEphemeralDPoPKeyPair('ES384');
    expect(kp.publicKey.algorithm).to.equal('ec:secp384r1');
  });

  it('generates ES512 (ec:secp521r1) key pair', async function () {
    const kp = await generateEphemeralDPoPKeyPair('ES512');
    expect(kp.publicKey.algorithm).to.equal('ec:secp521r1');
  });

  it('generates RS256 (rsa:2048) key pair', async function () {
    this.timeout(15_000);
    const kp = await generateEphemeralDPoPKeyPair('RS256');
    expect(kp.publicKey.algorithm).to.equal('rsa:2048');
  });

  it('throws on unknown algorithm', async function () {
    try {
      await generateEphemeralDPoPKeyPair('HS256');
      expect.fail('should have thrown');
    } catch (err) {
      expect((err as Error).message).to.include('Unsupported DPoP algorithm');
    }
  });
});

describe('resolveDPoPKeyPair', function () {
  it('returns undefined when both alg and keyPath are undefined', async function () {
    const result = await resolveDPoPKeyPair(undefined, undefined);
    expect(result).to.be.undefined;
  });

  it('returns an ES256 key pair when alg is ES256', async function () {
    const result = await resolveDPoPKeyPair('ES256', undefined);
    expect(result).to.not.be.undefined;
    expect(result!.publicKey.algorithm).to.equal('ec:secp256r1');
  });
});
