import AbstractPolicy from './AbstractPolicy';
import ResourceLocator from '../ResourceLocator';
import { RemotePolicyInterface } from '../../interfaces/PolicyInterface';
import PolicyTypeEnum from '../../enum/PolicyTypeEnum';

/**
 * Set remote policy body
 *
 * If the policy type is set to use a Remote Policy, then the Resource Locator object described in Section 3.4.1 is
 * used to describe the remote policy.
 */
class RemotePolicy extends AbstractPolicy implements RemotePolicyInterface {
  override readonly type: PolicyTypeEnum = PolicyTypeEnum.Remote;
  readonly remotePolicy: ResourceLocator;

  static override parse(buff: Uint8Array, bindingLength: number): { offset: number; policy: RemotePolicy } {
    let offset = 0;
    const resource = new ResourceLocator(buff);
    offset += resource.offset;

    const binding = buff.subarray(offset, offset + bindingLength);
    offset += bindingLength;

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
    const buffer = new Uint8Array(this.getLength());

    buffer.set([PolicyTypeEnum.Remote], 0);

    // Write the remote policy location
    const resourceLocatorAsBuf = this.remotePolicy.toBuffer();
    buffer.set(resourceLocatorAsBuf, 1);

    // Write the binding.
    buffer.set(this.binding, resourceLocatorAsBuf.length + 1);

    return buffer;
  }
}

export default RemotePolicy;
