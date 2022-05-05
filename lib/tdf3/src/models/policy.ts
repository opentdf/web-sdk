import { PolicyIntegrityError } from "../errors";

export const CURRENT_VERSION = '1.1.0';


export type AttributeObject = {
  attribute: string;
}

export type PolicyBody = {
  dataAttributesList: AttributeObject[];
  dissem: string[];
}

export type Policy = {
  tdf_spec_version?: string;
  uuid?: string;
  body?: PolicyBody;
}

export function validatePolicyObject(policy: unknown): policy is Policy {
  if (typeof policy !== "object") {
    throw new PolicyIntegrityError(
      `The given policy reference must be an object, not: ${policy}`
    );
  }
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
