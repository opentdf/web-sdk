import AbstractPolicy from './AbstractPolicy';
import EmbeddedPolicy from './EmbeddedPolicy';
import RemotePolicy from './RemotePolicy';
import PolicyTypeEnum from '../../enum/PolicyTypeEnum';
import { lengthOfBinding } from '../../helpers/calculateByCipher';
import InvalidPolicyTypeError from '../../errors/InvalidPolicyTypeError';
import CurveNameEnum from '../../enum/CurveNameEnum';

function parse(
  buff: Uint8Array,
  useEcdsaBinding: boolean,
  curve: CurveNameEnum
): { policy: AbstractPolicy; offset: number } | never {
  const type = buff[AbstractPolicy.TYPE_BYTE_OFF];
  const bindingLength = lengthOfBinding(useEcdsaBinding, curve);
  let policy: AbstractPolicy;
  let offset: number;

  // Check if remote policy
  if (type === PolicyTypeEnum.Remote) {
    ({ policy, offset } = RemotePolicy.parse(
      buff.subarray(AbstractPolicy.TYPE_BYTE_LEN),
      bindingLength
    ));
  } else if (
    [
      //  Check if is an embedded policy
      PolicyTypeEnum.EmbeddedEncrypted,
      PolicyTypeEnum.EmbeddedEncryptedPKA,
      PolicyTypeEnum.EmbeddedText,
    ].includes(type)
  ) {
    ({ policy, offset } = EmbeddedPolicy.parse(
      buff.subarray(AbstractPolicy.TYPE_BYTE_LEN),
      bindingLength,
      type
    ));
  } else {
    throw new InvalidPolicyTypeError();
  }

  return {
    policy,
    offset: offset + AbstractPolicy.TYPE_BYTE_LEN,
  };
}

export default {
  parse,
};
