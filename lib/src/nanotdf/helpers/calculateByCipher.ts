import { GMAC_BINDING_LEN } from '../constants.js';
import CurveNameEnum from '../enum/CurveNameEnum.js';
import { lengthOfSignature } from './calculateByCurve.js';

/**
 * Length of binding in bytes
 *
 * Get the binding length based on whether ECDSA binding is used and the curve name.
 * If no ECDSA then use GMAC binding.
 *
 * @param useEcdsaBinding boolean whether an ECDSA binding is used
 * @param curveName CurveNameEnum name of the curve
 * @returns number length of the binding
 */
export function lengthOfBinding(useEcdsaBinding: boolean, curve: CurveNameEnum): number | never {
  if (useEcdsaBinding) {
    return lengthOfSignature(curve);
  }
  return GMAC_BINDING_LEN;
}
