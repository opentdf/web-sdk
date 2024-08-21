import AbstractPolicy from './AbstractPolicy.js';
import EmbeddedPolicy from './EmbeddedPolicy.js';
import RemotePolicy from './RemotePolicy.js';
import PolicyTypeEnum from '../../enum/PolicyTypeEnum.js';
import { InvalidPolicyTypeError } from '../../../errors.js';
import CurveNameEnum from '../../enum/CurveNameEnum.js';

function parse(
  buff: Uint8Array,
  useEcdsaBinding: boolean,
  curve: CurveNameEnum
): { policy: AbstractPolicy; offset: number } | never {
  const type = buff[AbstractPolicy.TYPE_BYTE_OFF];
  let policy: AbstractPolicy;
  let offset: number;

  // Check if remote policy
  if (type === PolicyTypeEnum.Remote) {
    ({ policy, offset } = RemotePolicy.parse(
      buff.subarray(AbstractPolicy.TYPE_BYTE_LEN),
      useEcdsaBinding,
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
      useEcdsaBinding,
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
