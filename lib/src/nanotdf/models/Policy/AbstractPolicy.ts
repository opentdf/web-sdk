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
  static readonly SIZE_OF_LENGTH_FIELD = 1; // 1 byte for each length field (R and S)
  static readonly GMAC_BINDING_LEN = 8;

  readonly type: PolicyType;
  readonly binding: Uint8Array;

  // Static methods can't be defined in an interface
  static parse(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    buff: Uint8Array,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    useECDSABinding: boolean,
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

  /**
   * Parses an ECDSA binding from a given buffer.
   *
   * @param {Uint8Array} buff - The buffer containing the ECDSA binding.
   * @returns {{ bindingLength: number; binding: Uint8Array }} - An object containing the binding length and the binding subarray.
   */
  static parseECDSABinding(buff: Uint8Array): { bindingLength: number; binding: Uint8Array } {
    const lengthOfR = buff[0];
    const lengthOfS = buff[this.SIZE_OF_LENGTH_FIELD + lengthOfR];

    const bindingLength =
      this.SIZE_OF_LENGTH_FIELD + lengthOfR + this.SIZE_OF_LENGTH_FIELD + lengthOfS;
    const binding = buff.subarray(0, bindingLength);

    return { bindingLength, binding };
  }

  /**
   * Parses a binding from a given buffer based on the specified binding type.
   *
   * @param {Uint8Array} buff - The buffer containing the binding.
   * @param {boolean} useEcdsaBinding - Flag indicating whether to use ECDSA binding.
   * @param {number} offset - The starting offset in the buffer.
   * @returns {{ binding: Uint8Array; newOffset: number }} - An object containing the binding and the new offset.
   */
  static parseBinding(
    buff: Uint8Array,
    useEcdsaBinding: boolean,
    offset: number
  ): { binding: Uint8Array; newOffset: number } {
    if (useEcdsaBinding) {
      const ecdsaBinding = this.parseECDSABinding(buff.subarray(offset));
      return { binding: ecdsaBinding.binding, newOffset: offset + ecdsaBinding.bindingLength };
    } else {
      const binding = buff.subarray(offset, offset + this.GMAC_BINDING_LEN);
      return { binding, newOffset: offset + this.GMAC_BINDING_LEN };
    }
  }
}

export default AbstractPolicy;
