import type { JWTHeaderParameters, JWTPayload, JWTVerifyOptions } from 'jose';
import jwtClaimsSet from './vendor/lib/jwt_claims_set.js';

export default function joseJwtClaimsSet(
  protectedHeader: JWTHeaderParameters,
  encodedPayload: Uint8Array,
  options?: JWTVerifyOptions
): JWTPayload {
  return jwtClaimsSet(protectedHeader, encodedPayload, options) as JWTPayload;
}
