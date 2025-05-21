import { GetAttributeValuesByFqnsResponse } from '../platform/policy/attributes/attributes_pb.js';
import { AttributeRuleTypeEnum } from '../platform/policy/objects_pb.js';

export type KasPublicKey = Value['kasKeys'][number];
export type Value = NonNullable<
  GetAttributeValuesByFqnsResponse['fqnAttributeValues'][string]['value']
>;
export type KasPublicKeySet = {
  keys: KasPublicKey[];
};

export type Metadata = Value['metadata'];
export type KeyAccessServer = Value['grants'][number];
export type Attribute = Value['attribute'];
export type SubjectMapping = Value['subjectMappings'][number];
export type Namespace = NonNullable<Value['attribute']>['namespace'];
export type AttributeAndValue = {
  attribute: Attribute;
  value: Value;
};
export { AttributeRuleTypeEnum as AttributeRuleType };
