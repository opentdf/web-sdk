import type AttributeObject from './AttributeObject.ts';

export interface PolicyObjectBody {
  readonly dataAttributes: AttributeObject[];
  readonly dissem: string[];
}

export default interface PolicyObject {
  readonly uuid: string;
  readonly body: PolicyObjectBody;
  readonly schemaVersion?: string;
}
