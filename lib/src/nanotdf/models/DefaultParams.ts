import CipherEnum from '../enum/CipherEnum.js';
import CurveNameEnum from '../enum/CurveNameEnum.js';
import PolicyTypeEnum from '../enum/PolicyTypeEnum.js';

const enc = new TextEncoder();

/**
 * Default encrypt param builders
 *
 * @link https://github.com/virtru/tdf3-cpp/blob/develop/tdf3-src/lib/src/nanotdf_builder_impl.h
 */
const DefaultParams = {
  // Enabling ECDSA is not currently supported. Conflict with reusing key for `verify/sign` and `encrypt/decrypt`
  ecdsaBinding: false,
  ephemeralCurveName: CurveNameEnum.SECP256R1,
  magicNumberVersion: enc.encode('L1L'),
  offlineMode: false,
  policyType: PolicyTypeEnum.EmbeddedEncrypted,
  signature: false,
  signatureCurveName: CurveNameEnum.SECP256R1,
  symmetricCipher: CipherEnum.AES_256_GCM_96,
  defaultECAlgorithm: 'ec:secp256r1',
};

export default DefaultParams;
