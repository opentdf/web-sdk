import PolicyTypeEnum from '../enum/PolicyTypeEnum.ts';
import ResourceLocator from '../models/ResourceLocator.ts';

export default interface PolicyInterface {
  type: PolicyTypeEnum;
  binding: Uint8Array;

  // Remote policy
  remotePolicy?: ResourceLocator;

  // Embedded policy
  content?: Uint8Array;

  // Return the content of policy
  toBuffer(): Uint8Array | never;

  // Return the length of the policy
  getLength(): number;
}

export interface RemotePolicyInterface extends PolicyInterface {
  remotePoilcy?: ResourceLocator;
}

export interface EmbeddedPolicyInterface extends PolicyInterface {
  content: Uint8Array;
}
