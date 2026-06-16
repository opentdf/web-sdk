// cli/tests/dpop-helpers.spec.ts
import { expect } from '@esm-bundle/chai';
import { type webcrypto } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  derToPem,
  generateEphemeralDPoPKeyPair,
  loadDPoPKeyPairFromPem,
  resolveDPoPFromArgs,
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

type GeneratedPair = { privateKey: webcrypto.CryptoKey; publicKey: webcrypto.CryptoKey };

async function ecPrivatePem(curve: 'P-256' | 'P-384' | 'P-521'): Promise<string> {
  const raw = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, [
    'sign',
    'verify',
  ])) as GeneratedPair;
  const der = await crypto.subtle.exportKey('pkcs8', raw.privateKey);
  return derToPem(der, 'PRIVATE KEY');
}

async function rsaPrivatePem(): Promise<string> {
  const raw = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  )) as GeneratedPair;
  const der = await crypto.subtle.exportKey('pkcs8', raw.privateKey);
  return derToPem(der, 'PRIVATE KEY');
}

describe('loadDPoPKeyPairFromPem', function () {
  let tmpDir: string;

  before(async function () {
    tmpDir = await mkdtemp(join(tmpdir(), 'dpop-helpers-test-'));
  });

  after(async function () {
    await rm(tmpDir, { recursive: true, force: true });
  });

  async function writeTmp(name: string, contents: string): Promise<string> {
    const path = join(tmpDir, name);
    await writeFile(path, contents);
    return path;
  }

  it('loads a P-256 PEM into an ec:secp256r1 key pair', async function () {
    const path = await writeTmp('p256.pem', await ecPrivatePem('P-256'));
    const kp = await loadDPoPKeyPairFromPem(path);
    expect(kp.publicKey.algorithm).to.equal('ec:secp256r1');
  });

  it('loads a P-384 PEM into an ec:secp384r1 key pair', async function () {
    const path = await writeTmp('p384.pem', await ecPrivatePem('P-384'));
    const kp = await loadDPoPKeyPairFromPem(path);
    expect(kp.publicKey.algorithm).to.equal('ec:secp384r1');
  });

  it('loads a P-521 PEM into an ec:secp521r1 key pair', async function () {
    const path = await writeTmp('p521.pem', await ecPrivatePem('P-521'));
    const kp = await loadDPoPKeyPairFromPem(path);
    expect(kp.publicKey.algorithm).to.equal('ec:secp521r1');
  });

  it('loads an RSA-2048 PEM into an rsa:2048 key pair', async function () {
    this.timeout(15_000);
    const path = await writeTmp('rsa.pem', await rsaPrivatePem());
    const kp = await loadDPoPKeyPairFromPem(path);
    expect(kp.publicKey.algorithm).to.equal('rsa:2048');
  });

  it('throws CLIError when the file cannot be read', async function () {
    try {
      await loadDPoPKeyPairFromPem(join(tmpDir, 'does-not-exist.pem'));
      expect.fail('should have thrown');
    } catch (err) {
      expect((err as Error).message).to.include('Cannot read DPoP key file');
    }
  });

  it('throws CLIError when the PEM body is not valid base64', async function () {
    const path = await writeTmp(
      'corrupt.pem',
      '-----BEGIN PRIVATE KEY-----\n!!!not-base64!!!\n-----END PRIVATE KEY-----'
    );
    try {
      await loadDPoPKeyPairFromPem(path);
      expect.fail('should have thrown');
    } catch (err) {
      expect((err as Error).message).to.include('Cannot decode DPoP key file as PEM/base64');
    }
  });

  it('throws CLIError when the bytes are not a recognized key type', async function () {
    // Valid base64 but the decoded bytes are not a PKCS8 EC or RSA key.
    const path = await writeTmp(
      'garbage.pem',
      '-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----'
    );
    try {
      await loadDPoPKeyPairFromPem(path);
      expect.fail('should have thrown');
    } catch (err) {
      expect((err as Error).message).to.include('Cannot parse DPoP key from');
    }
  });
});

describe('resolveDPoPKeyPair', function () {
  let tmpDir: string;

  before(async function () {
    tmpDir = await mkdtemp(join(tmpdir(), 'dpop-resolve-test-'));
  });

  after(async function () {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('returns undefined when both alg and keyPath are undefined', async function () {
    const result = await resolveDPoPKeyPair(undefined, undefined);
    expect(result).to.be.undefined;
  });

  it('returns an ES256 key pair when alg is ES256', async function () {
    const result = await resolveDPoPKeyPair('ES256', undefined);
    expect(result).to.not.be.undefined;
    expect(result!.publicKey.algorithm).to.equal('ec:secp256r1');
  });

  it('loads from the keyPath PEM when only keyPath is provided', async function () {
    const path = join(tmpDir, 'p256-from-path.pem');
    await writeFile(path, await ecPrivatePem('P-256'));
    const result = await resolveDPoPKeyPair(undefined, path);
    expect(result).to.not.be.undefined;
    expect(result!.publicKey.algorithm).to.equal('ec:secp256r1');
  });

  it('prefers keyPath over alg when both are provided', async function () {
    const path = join(tmpDir, 'p384-pref.pem');
    await writeFile(path, await ecPrivatePem('P-384'));
    const result = await resolveDPoPKeyPair('ES256', path);
    expect(result).to.not.be.undefined;
    expect(result!.publicKey.algorithm).to.equal('ec:secp384r1');
  });
});

describe('resolveDPoPFromArgs', function () {
  let tmpDir: string;

  before(async function () {
    tmpDir = await mkdtemp(join(tmpdir(), 'dpop-args-test-'));
  });

  after(async function () {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('returns disabled when neither --dpop nor --dpopKey is set', async function () {
    const result = await resolveDPoPFromArgs({});
    expect(result.dpopEnabled).to.be.false;
    expect(result.dpopKeyPair).to.be.undefined;
  });

  it('defaults to ES256 when --dpop is passed without a value', async function () {
    // yargs delivers a bare `--dpop` as the empty string for type: 'string'
    const result = await resolveDPoPFromArgs({ dpop: '' });
    expect(result.dpopEnabled).to.be.true;
    expect(result.dpopKeyPair?.publicKey.algorithm).to.equal('ec:secp256r1');
  });

  it('honours an explicit --dpop=ES384', async function () {
    const result = await resolveDPoPFromArgs({ dpop: 'ES384' });
    expect(result.dpopEnabled).to.be.true;
    expect(result.dpopKeyPair?.publicKey.algorithm).to.equal('ec:secp384r1');
  });

  it('enables DPoP from --dpopKey alone (no --dpop)', async function () {
    const path = join(tmpDir, 'args-key.pem');
    await writeFile(path, await ecPrivatePem('P-256'));
    const result = await resolveDPoPFromArgs({ dpopKey: path });
    expect(result.dpopEnabled).to.be.true;
    expect(result.dpopKeyPair?.publicKey.algorithm).to.equal('ec:secp256r1');
  });

  it('propagates the CLIError for an invalid algorithm', async function () {
    try {
      await resolveDPoPFromArgs({ dpop: 'INVALID' });
      expect.fail('should have thrown');
    } catch (err) {
      expect((err as Error).message).to.include('Unsupported DPoP algorithm');
    }
  });
});
