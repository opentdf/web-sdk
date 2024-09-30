import {
  AssertionKeyAlg,
  AssertionType,
  Scope,
  AppliesToState,
  Statement,
} from '../models/assertion.js';

export type AssertionKey = {
  alg: AssertionKeyAlg;
  key: any; // Replace AnyKey with the actual type of your key
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

// AssertionVerificationKeys represents the verification keys for assertions.
export type AssertionVerificationKeys = {
  DefaultKey?: AssertionKey;
  Keys: Record<string, AssertionKey>;
};
