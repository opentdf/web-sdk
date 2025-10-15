import { expect, assert } from 'chai';
import { getRootCertsFromNamespace } from '../../src/policy/api.js';

// Basic unit tests for policy API helpers
// Focus: input validation for getRootCertsFromNamespace

describe('policy api - getRootCertsFromNamespace', () => {
  const platformUrl = 'http://localhost:3000';

  it('throws when neither namespaceId nor fqn is provided', async () => {
    try {
      await getRootCertsFromNamespace(platformUrl);
      assert.fail('Expected getRootCertsFromNamespace to throw when identifiers are missing');
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).to.equal('Either namespaceId or fqn must be provided');
    }
  });
});
