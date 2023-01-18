import CurveNameEnum from '../enum/CurveNameEnum.js';
import EcCurves from '../models/EcCurves.js';

/**
 * Length of public key
 *
 * @param curveName CurveNameEnum
 * @returns number length of the public key
 */
export function lengthOfPublicKey(curveName: CurveNameEnum): number | never {
  return Math.ceil(EcCurves.getCurveLength(curveName) / 8);
}

/**
 * Length of signature
 *
 * ECDSA signatures are 2 times longer than the signer's private key for the curve used during the signing process.
 * For example, for 256-bit elliptic curves (like secp256k1 ) the ECDSA signature is 512 bits (64 bytes) and for 521-bit
 * curves (like secp521r1 ) the signature is 1042 bits.
 *
 * @param curveName CurveNameEnum
 * @returns number length of the signature
 */
export function lengthOfSignature(curveName: CurveNameEnum): number | never {
  return Math.ceil((EcCurves.getCurveLength(curveName) * 2) / 8);
}
