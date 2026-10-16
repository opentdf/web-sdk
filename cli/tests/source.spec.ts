import { expect } from '@esm-bundle/chai';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CLIError } from '../src/logger.js';
import { PlaintextRangeError } from '@opentdf/sdk';
import {
  asRangeCliError,
  fromLocalFile,
  parseByteCount,
  rangeFromArgs,
  tdfSource,
} from '../src/source.js';

describe('parseByteCount', function () {
  it('accepts decimal integers, including past 4 GiB', function () {
    expect(parseByteCount('offset', '0')).to.equal(0);
    expect(parseByteCount('offset', '5000000000')).to.equal(5_000_000_000);
    expect(parseByteCount('offset', String(Number.MAX_SAFE_INTEGER))).to.equal(
      Number.MAX_SAFE_INTEGER
    );
  });

  for (const bad of ['-1', '1.5', '1e3', '0x10', '', 'abc', '9007199254740992']) {
    it(`rejects ${JSON.stringify(bad)}`, function () {
      expect(() => parseByteCount('offset', bad)).to.throw(CLIError, '--offset');
    });
  }
});

describe('rangeFromArgs', function () {
  it('is absent without either flag', function () {
    expect(rangeFromArgs({})).to.equal(undefined);
  });

  it('reads to the end without --length', function () {
    expect(rangeFromArgs({ offset: '10' })).to.deep.equal({ offset: 10 });
  });

  it('reads from the start without --offset', function () {
    expect(rangeFromArgs({ length: '10' })).to.deep.equal({ offset: 0, length: 10 });
  });

  it('takes both', function () {
    expect(rangeFromArgs({ offset: '4294967306', length: '0' })).to.deep.equal({
      offset: 4294967306,
      length: 0,
    });
  });

  it('rejects a bad length', function () {
    expect(() => rangeFromArgs({ offset: '1', length: '-5' })).to.throw(CLIError, '--length');
  });
});

describe('asRangeCliError', function () {
  it('reports an unsatisfiable range as a CLI error', function () {
    const e = asRangeCliError(
      new PlaintextRangeError('range offset [11] is past the end of the plaintext [10]')
    );
    expect(e).to.be.instanceOf(CLIError);
    expect((e as CLIError).prefix).to.equal('CRITICAL');
    expect((e as Error).message).to.equal(
      'range offset [11] is past the end of the plaintext [10]'
    );
  });

  it('passes other errors through', function () {
    const other = new Error('boom');
    expect(asRangeCliError(other)).to.equal(other);
  });
});

describe('local file sources', function () {
  let dir: string;
  before(async function () {
    dir = await mkdtemp(join(tmpdir(), 'opentdf-cli-'));
  });
  after(async function () {
    await rm(dir, { recursive: true, force: true });
  });

  it('follows Chunker semantics', async function () {
    const path = join(dir, 'ten');
    await writeFile(path, new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]));
    const chunker = fromLocalFile(path, 10);
    expect([...(await chunker())]).to.deep.equal([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect([...(await chunker(3, 6))]).to.deep.equal([3, 4, 5]);
    expect([...(await chunker(7))]).to.deep.equal([7, 8, 9]);
    expect([...(await chunker(-2))]).to.deep.equal([8, 9]);
    expect([...(await chunker(-20))]).to.deep.equal([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect([...(await chunker(8, 100))]).to.deep.equal([8, 9]);
    expect(await chunker(5, 5)).to.have.length(0);
  });

  it('reads past 4 GiB', async function () {
    // A sparse file, so this costs no real disk space.
    const path = join(dir, 'big');
    const size = 2 ** 32 + 100;
    const handle = await open(path, 'w');
    try {
      await handle.truncate(size);
      await handle.write(new Uint8Array([42, 43]), 0, 2, 2 ** 32 + 10);
    } finally {
      await handle.close();
    }
    const chunker = fromLocalFile(path, size);
    expect([...(await chunker(2 ** 32 + 9, 2 ** 32 + 13))]).to.deep.equal([0, 42, 43, 0]);
    expect(await chunker(-100)).to.have.length(100);
  });

  it('uses ranged reads for a local file and fromUrl for a URL', async function () {
    const path = join(dir, 'ten');
    expect((await tdfSource(path)).type).to.equal('chunker');
    expect(await tdfSource('https://example.com/a.tdf')).to.deep.equal({
      type: 'remote',
      location: 'https://example.com/a.tdf',
    });
  });

  it('rejects a missing file', async function () {
    try {
      await tdfSource(join(dir, 'missing'));
      expect.fail('expected a CLIError');
    } catch (e) {
      expect(e).to.be.instanceOf(CLIError);
      expect((e as Error).message).to.contain('not accessable');
    }
  });
});
