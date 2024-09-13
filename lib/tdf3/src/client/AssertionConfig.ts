
import { AssertionType, Scope, AppliesToState, Statement } from '../models/assertion.js';

export type AssertionKey = {
  alg: string;
  key: any; // CryptoKey
};

// AssertionConfig is a shadow of Assertion with the addition of the signing key.
// It is used on creation of the assertion.
export type AssertionConfig = {
  id: string;
  type: AssertionType;
  scope: Scope;
  appliesToState: AppliesToState;
  statement: Statement;
  signingKey?: AssertionKey;
};

