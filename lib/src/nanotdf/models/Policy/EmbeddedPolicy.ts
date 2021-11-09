import AbstractPolicy from './AbstractPolicy.js';
import { EmbeddedPolicyInterface } from '../../interfaces/PolicyInterface.js';
import PolicyTypes from '../../enum/PolicyTypeEnum.js';

/**
 * Embedded Policy
 *
 * These policy types allow for creation and binding of arbitrary policies.
 *
 * | Section                      | Minimum Length (B) | Maximum Length (B) |
 * |------------------------------|--------------------|--------------------|
 * | Content Length               | 2                  | 2                  |
 * | Plaintext/Ciphertext         | 1                  | 255                |
 * | (Optional) Policy Key Access | 36                 | 136                |
 */
class EmbeddedPolicy extends AbstractPolicy implements EmbeddedPolicyInterface {
  static MAX_POLICY_SIZE = 65535; // 2 bytes unsigned int.
  readonly content: Uint8Array;

  static parse(
    buff: Uint8Array,
    bindingLength: number,
    type: PolicyTypes
  ): { offset: number; policy: EmbeddedPolicy } {
    let offset = 0;

    // TODO: May not work on Big Endian systems. See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView/getUint16
    // Also http://calculist.org/blog/2012/04/24/the-little-endian-web/
    const length = new DataView(buff.slice(offset, 2).buffer).getUint16(0);
    offset += 2;

    const content = buff.subarray(offset, offset + length);
    offset += length;

    const binding = buff.subarray(offset, offset + bindingLength);
    offset += bindingLength;

    return {
      policy: new EmbeddedPolicy(type, binding, content),
      offset,
    };
  }

  constructor(type: PolicyTypes, binding: Uint8Array, content: Uint8Array) {
    super(type, binding);
    this.content = content;
  }

  /**
   * Length of policy
   *
   * @returns { number } length
   */
  getLength(): number {
    return (
      // Type length
      1 +
      // Policy length
      2 +
      // Content length
      this.content.length +
      // Binding length
      this.binding.length
    );
  }

  /**
   * Return the content of the policy
   */
  toBuffer(): Uint8Array {
    const buffer = new Uint8Array(this.getLength());

    if (this.content.length > EmbeddedPolicy.MAX_POLICY_SIZE) {
      throw new Error("TDF Policy can't be more that 2^16");
    }

    buffer.set([this.type], 0);

    // Write the policy length, assuming the host system is little endian
    // TODO: There should be better way to convert to big endian
    const lengthAsUint16 = new Uint16Array(1);
    lengthAsUint16[0] = this.content.length;

    const temp = new Uint8Array(lengthAsUint16.buffer);
    const policyContentSizeAsBg = new Uint8Array(2);
    policyContentSizeAsBg[0] = temp[1];
    policyContentSizeAsBg[1] = temp[0];
    buffer.set(policyContentSizeAsBg, 1);

    // Write the policy content
    buffer.set(this.content, policyContentSizeAsBg.length + 1);

    // Write the binding.
    buffer.set(this.binding, this.content.length + policyContentSizeAsBg.length + 1);

    return buffer;
  }
}

export default EmbeddedPolicy;
