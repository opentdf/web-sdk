import { expect } from '@esm-bundle/chai';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CLIError } from '../src/logger.js';
import { parseAssertionVerificationKeys } from '../src/assertion-keys.js';

const pem = '-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----';
const utf8 = (s: string) => new TextEncoder().encode(s);

describe('parseAssertionVerificationKeys', function () {
  it('reads per-ID keys and the default key', async function () {
    const keys = await parseAssertionVerificationKeys(
      JSON.stringify({
        keys: { a1: { alg: 'RS256', key: pem }, a2: { alg: 'HS256', key: 'secret' } },
        defaultKey: { alg: 'HS256', key: 'default secret' },
      })
    );
    expect(keys.Keys.a1).to.deep.equal({ alg: 'RS256', key: pem });
    expect(keys.Keys.a2).to.deep.equal({ alg: 'HS256', key: utf8('secret') });
    expect(keys.DefaultKey).to.deep.equal({ alg: 'HS256', key: utf8('default secret') });
  });

  it('accepts the capitalized spellings', async function () {
    const keys = await parseAssertionVerificationKeys(
      JSON.stringify({
        Keys: { a1: { alg: 'RS256', key: pem } },
        DefaultKey: { alg: 'RS256', key: pem },
      })
    );
    expect(keys.Keys.a1).to.deep.equal({ alg: 'RS256', key: pem });
    expect(keys.DefaultKey).to.deep.equal({ alg: 'RS256', key: pem });
  });

  it('accepts a default key on its own', async function () {
    const keys = await parseAssertionVerificationKeys(
      JSON.stringify({ defaultKey: { alg: 'RS256', key: pem } })
    );
    expect(keys.Keys).to.deep.equal({});
    expect(keys.DefaultKey).to.deep.equal({ alg: 'RS256', key: pem });
  });

  it('leaves the default key unset when it is absent', async function () {
    const keys = await parseAssertionVerificationKeys(
      JSON.stringify({ keys: { a1: { alg: 'RS256', key: pem } } })
    );
    expect(keys).to.not.have.property('DefaultKey');
  });

  it('keeps unusual ids as ordinary entries', async function () {
    const keys = await parseAssertionVerificationKeys(
      '{"keys":{"__proto__":{"alg":"RS256","key":"k"},"constructor":{"alg":"HS256","key":"s"}}}'
    );
    expect(Object.getPrototypeOf(keys.Keys)).to.equal(Object.prototype);
    expect(Object.keys(keys.Keys)).to.deep.equal(['__proto__', 'constructor']);
  });

  it('reads a keys file', async function () {
    const dir = await mkdtemp(join(tmpdir(), 'assertion-keys-'));
    try {
      const file = join(dir, 'keys.json');
      await writeFile(file, JSON.stringify({ defaultKey: { alg: 'HS256', key: 's' } }));
      const keys = await parseAssertionVerificationKeys(file);
      expect(keys.DefaultKey).to.deep.equal({ alg: 'HS256', key: utf8('s') });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('treats an empty default key as not configured', async function () {
    for (const defaultKey of [{}, { alg: '', key: '' }, null]) {
      const keys = await parseAssertionVerificationKeys(
        JSON.stringify({ keys: { a1: { alg: 'RS256', key: pem } }, defaultKey })
      );
      expect(keys).to.not.have.property('DefaultKey');
    }
  });

  for (const [what, input] of [
    ['neither keys nor a default key', '{}'],
    ['keys that are not an object', '{"keys":"a1"}'],
    ['a default key that is not an object', '{"keys":{},"defaultKey":"secret"}'],
    ['a default key without alg', '{"defaultKey":{"key":"secret"}}'],
    ['a default key with an unsupported alg', '{"defaultKey":{"alg":"PS256","key":"k"}}'],
    ['an HS256 key that is not a string', '{"defaultKey":{"alg":"HS256","key":7}}'],
    ['a per-ID key without alg', '{"keys":{"a1":{"key":"k"}}}'],
    ['a per-ID key that is empty', '{"keys":{"a1":{}}}'],
    ['a lowercase alg', '{"defaultKey":{"alg":"rs256","key":"k"}}'],
    ['an alg without a key', '{"defaultKey":{"alg":"ES512"}}'],
    ['an unknown top-level member', '{"keys":{},"default_key":{"alg":"HS256","key":"s"}}'],
    ['an array', '[]'],
  ]) {
    it(`rejects ${what}`, async function () {
      let error: unknown;
      try {
        await parseAssertionVerificationKeys(input);
      } catch (e) {
        error = e;
      }
      expect(error).to.be.instanceOf(CLIError);
      expect((error as Error).message).to.contain('reason=configuration-error');
    });
  }
});
