import type { JWTHeaderParameters, JWTPayload, JWTVerifyOptions } from 'jose';
import { validateClaimsSet } from './vendor/index.js';

export default function joseJwtClaimsSet(
  protectedHeader: JWTHeaderParameters,
  encodedPayload: Uint8Array,
  options?: JWTVerifyOptions
): JWTPayload {
  return validateClaimsSet(protectedHeader, encodedPayload, options) as JWTPayload;
}
