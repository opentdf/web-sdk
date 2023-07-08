/**
 * The Signature ECC Mode is used to determine the length of the signature at the end of a nanotdf. This, in
 * combination with the previous HAS_SIGNATURE section, describe the signature of the nanotdf. The following table
 * describes the valid values and the associated ECC Params.
 */
enum CurveNameEnum {
  SECP256R1,
  SECP384R1,
  SECP521R1,
}

export default CurveNameEnum;
