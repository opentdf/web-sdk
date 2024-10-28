import { type AssertionConfig } from './client/AssertionConfig.js';

export {
  type AssertionConfig,
  type AssertionKey,
  type AssertionVerificationKeys,
} from './client/AssertionConfig.js';

export { type Assertion, CreateAssertion } from './models/assertion.js';

// a function that takes an unknown or any object and asserts that it is or is not an AssertionConfig object
export function isAssertionConfig(obj: unknown): obj is AssertionConfig {
  return (
    !!obj &&
    typeof obj === 'object' &&
    'id' in obj &&
    typeof obj.id === 'string' &&
    'type' in obj &&
    (obj.type === 'handling' || obj.type === 'other') &&
    'scope' in obj &&
    (obj.scope === 'tdo' || obj.scope === 'payload') &&
    'appliesToState' in obj &&
    (obj.appliesToState === 'encrypted' || obj.appliesToState === 'unencrypted') &&
    'statement' in obj &&
    !!obj.statement &&
    typeof obj.statement === 'object' &&
    'format' in obj.statement &&
    'schema' in obj.statement &&
    'value' in obj.statement
  );
}
