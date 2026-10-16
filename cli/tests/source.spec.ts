import { expect } from '@esm-bundle/chai';
import { CLIError } from '../src/logger.js';
import { PlaintextRangeError } from '@opentdf/sdk';
import { asRangeCliError, isUrl, parseByteCount, rangeFromArgs } from '../src/source.js';

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

describe('isUrl', function () {
  it('accepts http and https URLs only', function () {
    expect(isUrl('https://example.com/a.tdf')).to.be.true;
    expect(isUrl('HTTP://example.com/a.tdf')).to.be.true;
    expect(isUrl('file:///tmp/a.tdf')).to.be.false;
    expect(isUrl('/tmp/https://a.tdf')).to.be.false;
  });
});
