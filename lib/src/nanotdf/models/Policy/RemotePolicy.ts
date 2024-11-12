import AbstractPolicy from './AbstractPolicy.js';
import ResourceLocator from '../ResourceLocator.js';
import { RemotePolicyInterface } from '../../interfaces/PolicyInterface.js';
import PolicyTypeEnum from '../../enum/PolicyTypeEnum.js';

/**
 * Set remote policy body
 *
 * If the policy type is set to use a Remote Policy, then the Resource Locator object described in Section 3.4.1 is
 * used to describe the remote policy.
 */
class RemotePolicy extends AbstractPolicy implements RemotePolicyInterface {
  override readonly type: PolicyTypeEnum = PolicyTypeEnum.Remote;
  readonly remotePolicy: ResourceLocator;

  static override parse(
    buff: Uint8Array,
    useEcdsaBinding: boolean
  ): { offset: number; policy: RemotePolicy } {
    let offset = 0;
    const resource = ResourceLocator.parse(buff);
    offset += resource.offset;

    const { binding, newOffset: bindingOffset } = this.parseBinding(buff, useEcdsaBinding, offset);
    offset = bindingOffset;

    return {
      policy: new RemotePolicy(PolicyTypeEnum.Remote, binding, resource),
      offset,
    };
  }

  constructor(type: PolicyTypeEnum, binding: Uint8Array, resource: ResourceLocator) {
    super(type, binding);
    this.type = PolicyTypeEnum.Remote;
    this.remotePolicy = resource;
  }

  /**
   * Length of policy
   *
   * @returns { number } length
   */
  override getLength(): number {
    return (
      // Type length
      1 +
      // Resource locator length
      this.remotePolicy.length +
      // Binding length
      this.binding.length
    );
  }

  /**
   * Return the content of the policy
   */
  override toBuffer(): Uint8Array {
    const target = new Uint8Array(this.getLength());

    target.set([PolicyTypeEnum.Remote], 0);

    // Write the remote policy location
    const resourceLocatorAsBuf = this.remotePolicy.toBuffer();
    target.set(resourceLocatorAsBuf, 1);

    // Write the binding.
    target.set(this.binding, resourceLocatorAsBuf.length + 1);

    return target;
  }
}

export default RemotePolicy;
