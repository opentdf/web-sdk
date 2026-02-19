import { expect, assert } from 'chai';
import {
  validateAttributes,
  validateAttributeExists,
  validateAttributeValue,
} from '../../../src/policy/discovery.js';
import { AttributeNotFoundError, ConfigurationError } from '../../../src/errors.js';

// Null/stub auth provider — not needed for validation-only code paths.
const noopAuthProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (req: unknown) => req,
} as never;

const platformUrl = 'http://localhost:3000';

describe('discovery - validateAttributes', () => {
  it('returns immediately for null input', async () => {
    await validateAttributes(platformUrl, noopAuthProvider, null as never);
  });

  it('returns immediately for empty array', async () => {
    await validateAttributes(platformUrl, noopAuthProvider, []);
  });

  it('throws ConfigurationError for insecure platformUrl', async () => {
    try {
      await validateAttributes('http://example.com', noopAuthProvider, [
        'https://example.com/attr/a/value/v',
      ]);
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('platformUrl must use HTTPS');
    }
  });

  it('throws ConfigurationError when too many FQNs are provided', async () => {
    const fqns = Array.from({ length: 251 }, (_, i) => `https://example.com/attr/a/value/v${i}`);
    try {
      await validateAttributes(platformUrl, noopAuthProvider, fqns);
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('too many attribute FQNs');
    }
  });

  it('throws ConfigurationError for an invalid FQN format', async () => {
    try {
      await validateAttributes(platformUrl, noopAuthProvider, ['not-a-valid-fqn']);
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
    }
  });

  it('throws ConfigurationError for an FQN missing the /attr/ segment', async () => {
    try {
      await validateAttributes(platformUrl, noopAuthProvider, [
        'https://example.com/department/marketing',
      ]);
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
    }
  });

  it('throws ConfigurationError for an FQN missing the /value/ segment', async () => {
    try {
      await validateAttributes(platformUrl, noopAuthProvider, [
        'https://example.com/attr/department',
      ]);
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
    }
  });

  it('throws ConfigurationError for FQN with HTML tags (XSS prevention)', async () => {
    try {
      await validateAttributes(platformUrl, noopAuthProvider, [
        'https://example.com/attr/<script>/value/alert',
      ]);
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
    }
  });

  it('throws ConfigurationError for FQN with special characters', async () => {
    try {
      await validateAttributes(platformUrl, noopAuthProvider, [
        'https://example.com/attr/test&param=1/value/test',
      ]);
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
    }
  });
});

describe('discovery - validateAttributeExists', () => {
  it('throws ConfigurationError for an invalid FQN format', async () => {
    try {
      await validateAttributeExists(platformUrl, noopAuthProvider, 'bad-fqn-format');
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
    }
  });
});

describe('discovery - validateAttributeValue', () => {
  it('throws ConfigurationError for an empty value string', async () => {
    try {
      await validateAttributeValue(
        platformUrl,
        noopAuthProvider,
        'https://example.com/attr/clearance',
        ''
      );
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('must not be empty');
    }
  });

  it('throws ConfigurationError for insecure platformUrl', async () => {
    try {
      await validateAttributeValue(
        'http://example.com',
        noopAuthProvider,
        'https://example.com/attr/clearance',
        'secret'
      );
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('platformUrl must use HTTPS');
    }
  });

  it('throws ConfigurationError for a value FQN passed as attributeFqn', async () => {
    // A full value FQN (containing /value/) is not a valid attribute-level FQN.
    try {
      await validateAttributeValue(
        platformUrl,
        noopAuthProvider,
        'https://example.com/attr/clearance/value/secret',
        'secret'
      );
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute FQN');
    }
  });

  it('throws ConfigurationError for a non-URL attributeFqn', async () => {
    try {
      await validateAttributeValue(platformUrl, noopAuthProvider, 'not-a-fqn', 'somevalue');
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute FQN');
    }
  });
});

// Verify the error type hierarchy is correct.
describe('AttributeNotFoundError', () => {
  it('is an instance of Error', () => {
    const err = new AttributeNotFoundError('test');
    expect(err).to.be.instanceOf(Error);
    expect(err.name).to.equal('AttributeNotFoundError');
    expect(err.message).to.equal('test');
  });
});
