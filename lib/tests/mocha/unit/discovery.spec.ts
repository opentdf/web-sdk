import { expect, assert } from 'chai';
import {
  validateAttributes,
  attributeExists,
  attributeValueExists,
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

describe('discovery - attributeExists', () => {
  it('throws ConfigurationError for insecure platformUrl', async () => {
    try {
      await attributeExists(
        'http://example.com',
        noopAuthProvider,
        'https://example.com/attr/clearance'
      );
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('platformUrl must use HTTPS');
    }
  });

  it('throws ConfigurationError for an invalid attribute FQN format', async () => {
    try {
      await attributeExists(platformUrl, noopAuthProvider, 'not-a-valid-fqn');
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute FQN');
    }
  });

  it('throws ConfigurationError when passed a value FQN (with /value/)', async () => {
    // A full value FQN is not a valid attribute-level FQN.
    try {
      await attributeExists(
        platformUrl,
        noopAuthProvider,
        'https://example.com/attr/clearance/value/secret'
      );
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute FQN');
    }
  });
});

describe('discovery - attributeValueExists', () => {
  it('throws ConfigurationError for insecure platformUrl', async () => {
    try {
      await attributeValueExists(
        'http://example.com',
        noopAuthProvider,
        'https://example.com/attr/clearance/value/secret'
      );
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('platformUrl must use HTTPS');
    }
  });

  it('throws ConfigurationError for an invalid FQN format', async () => {
    try {
      await attributeValueExists(platformUrl, noopAuthProvider, 'not-a-valid-fqn');
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
    }
  });

  it('throws ConfigurationError when passed an attribute-level FQN (no /value/)', async () => {
    // An attribute-level FQN without /value/ is not a valid value FQN.
    try {
      await attributeValueExists(
        platformUrl,
        noopAuthProvider,
        'https://example.com/attr/clearance'
      );
      assert.fail('expected to throw');
    } catch (e) {
      expect(e).to.be.instanceOf(ConfigurationError);
      expect((e as Error).message).to.include('invalid attribute value FQN');
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
