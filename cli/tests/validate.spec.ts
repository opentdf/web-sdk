import { expect } from '@esm-bundle/chai';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { type FixtureEntry, writeZip64 } from './zip-fixture.js';

const cli = fileURLToPath(new URL('../../bin/opentdf.mjs', import.meta.url));

/** The smallest manifest the lax schema accepts. */
const manifest = {
  payload: { type: 'reference', url: '0.payload', protocol: 'zip', isEncrypted: true },
  encryptionInformation: {},
};
const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

/**
 * Runs `opentdf validate` with no other options: no platform, KAS or OIDC
 * endpoint and no credentials, so any attempt to use them fails the test.
 */
function validate(...args: string[]) {
  const { status, stdout, stderr } = spawnSync(process.execPath, [cli, 'validate', ...args], {
    encoding: 'utf8',
  });
  return { status, stdout, stderr };
}

/** Parses stdout, which must be exactly one JSON line. */
function resultOf(stdout: string): unknown {
  expect(stdout.endsWith('\n'), 'stdout ends with a newline').to.equal(true);
  const lines = stdout.slice(0, -1).split('\n');
  expect(lines, 'stdout lines').to.have.length(1);
  return JSON.parse(lines[0]);
}

describe('validate command', function () {
  // Each case starts a CLI process.
  this.timeout(30_000);
  let dir: string;
  before(async function () {
    dir = await mkdtemp(join(tmpdir(), 'validate-'));
  });
  after(async function () {
    await rm(dir, { recursive: true, force: true });
  });

  const tdf = async (name: string, entries: FixtureEntry[]) => {
    const path = join(dir, name);
    await writeZip64(path, entries);
    return path;
  };

  it('exits 0 and prints {"valid":true} for a valid TDF', async function () {
    const path = await tdf('valid.tdf', [
      { name: '0.payload', data: new Uint8Array(16) },
      { name: '0.manifest.json', data: json(manifest) },
    ]);
    const { status, stdout, stderr } = validate(path);
    expect(status, stderr).to.equal(0);
    expect(stdout).to.equal('{"valid":true}\n');
  });

  it('exits 3 with a reason for a file that is not a ZIP archive', async function () {
    const path = join(dir, 'garbage.tdf');
    await writeFile(path, 'this is not a TDF');
    const { status, stdout, stderr } = validate(path);
    expect(status, stderr).to.equal(3);
    const result = resultOf(stdout) as { valid: boolean; reason: string };
    expect(result.valid).to.equal(false);
    expect(result.reason).to.contain('end of central directory');
    expect(Object.keys(result)).to.deep.equal(['valid', 'reason']);
  });

  it('exits 3 with a reason for a manifest that fails the schema', async function () {
    const path = await tdf('schema.tdf', [
      { name: '0.manifest.json', data: json({}) },
      { name: '0.payload', data: new Uint8Array(16) },
    ]);
    const { status, stdout, stderr } = validate(path);
    expect(status, stderr).to.equal(3);
    const result = resultOf(stdout) as { valid: boolean; reason: string };
    expect(result.valid).to.equal(false);
    expect(result.reason).to.contain('lax schema');
  });

  for (const [name, args] of [
    ['a missing file', ['does-not-exist.tdf']],
    ['no file argument', []],
  ] as const) {
    it(`exits nonzero, but not 3, and prints nothing to stdout for ${name}`, function () {
      const { status, stdout, stderr } = validate(...args.map((arg) => join(dir, arg)));
      expect(status, stderr).to.not.equal(0);
      expect(status, stderr).to.not.equal(3);
      expect(stdout).to.equal('');
    });
  }

  // DSPX-5160: through fs.openAsBlob, Node reports this file's size modulo 2^32,
  // so the archive tail would be read from the wrong place and a valid TDF would
  // fail. The payload is a hole, so the file takes a few KiB on disk.
  it('validates a TDF of 4 GiB or more', async function () {
    const path = await tdf('large.tdf', [
      { name: '0.payload', size: 2 ** 32 + 4096 },
      { name: '0.manifest.json', data: json(manifest) },
    ]);
    const { status, stdout, stderr } = validate(path);
    expect(status, stderr).to.equal(0);
    expect(stdout).to.equal('{"valid":true}\n');
  });
});
