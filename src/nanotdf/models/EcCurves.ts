import CurveNameEnum from '../enum/CurveNameEnum.js';
import InvalidCurveNameError from '../errors/InvalidCurveNameError.js';

interface CurveInterface {
  name: CurveNameEnum;
  length: number;
}

export const Secp256R1: CurveInterface = {
  name: CurveNameEnum.SECP256R1,
  length: 256,
};

export const Secp384R1: CurveInterface = {
  name: CurveNameEnum.SECP384R1,
  length: 384,
};

export const Secp521R1: CurveInterface = {
  name: CurveNameEnum.SECP521R1,
  length: 521,
};

/**
 * Get size from Curve
 *
 * @param curveName CurveNameEnum name of the curve
 */
function getCurveLength(curveName: CurveNameEnum): number {
  switch (curveName) {
    case Secp256R1.name:
      return Secp256R1.length;
    case Secp384R1.name:
      return Secp384R1.length;
    case Secp521R1.name:
      return Secp521R1.length;
    default:
      throw new InvalidCurveNameError();
  }
}

export default {
  Secp256R1,
  Secp384R1,
  Secp521R1,

  getCurveLength,
};
