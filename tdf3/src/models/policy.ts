import { PolicyIntegrityError } from '../errors.js';
import { AttributeObject } from './attribute-set.js';

export const CURRENT_VERSION = '1.1.0';

export type PolicyBody = {
  dataAttributes: AttributeObject[];
  dissem: string[];
};

export type Policy = {
  tdf_spec_version?: string;
  uuid?: string;
  body?: PolicyBody;
};

export function validatePolicyObject(policyMaybe: unknown): policyMaybe is Policy {
  if (typeof policyMaybe !== 'object') {
    throw new PolicyIntegrityError(
      `The given policy reference must be an object, not: ${policyMaybe}`
    );
  }
  const policy = policyMaybe as Policy;
  const missingFields = [];
  if (!policy.uuid) missingFields.push('uuid');
  if (!policy.body) missingFields.push('body', 'body.dissem');
  if (policy.body && !policy.body.dissem) missingFields.push('body.dissem');

  if (missingFields.length) {
    throw new PolicyIntegrityError(
      `The given policy object requires the following properties: ${missingFields}`
    );
  }
  return true;
}
