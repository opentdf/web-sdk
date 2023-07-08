import PolicyInterface from '../../interfaces/PolicyInterface.js';
import PolicyType from '../../enum/PolicyTypeEnum.js';

abstract class AbstractPolicy implements PolicyInterface {
  static readonly TYPE_BYTE_OFF = 0;
  static readonly TYPE_BYTE_LEN = 1;
  static readonly BODY_BYTE_OFF = 1;
  static readonly BODY_BYTE_MIN_LEN = 3;
  static readonly BODY_BYTE_MAX_LEN = 257;
  static readonly BINDING_BYTE_MIN_LEN = 8;
  static readonly BINDING_BYTE_MAX_LEN = 132;

  readonly type: PolicyType;
  readonly binding: Uint8Array;

  // Static methods can't be defined in an interface
  static parse(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    buff: Uint8Array,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    bindingLength: number,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    type?: PolicyType
  ): { policy: PolicyInterface; offset: number } {
    throw new Error('parsePolicy was not implemented');
  }

  constructor(type: PolicyType, binding: Uint8Array) {
    this.type = type;
    this.binding = binding;
  }

  /**
   * Length of policy
   */
  getLength(): number | never {
    throw new Error('length was not implemented');
  }

  /**
   * Return the content of the policy
   */
  toBuffer(): Uint8Array | never {
    throw new Error('toBuffer() was not implemented');
  }
}

export default AbstractPolicy;
