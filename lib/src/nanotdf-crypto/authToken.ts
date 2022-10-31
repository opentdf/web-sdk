import { JWTPayload, SignJWT } from 'jose';
import { AlgorithmName } from './enums.js';

/**
 * Get auth token from private key
 *
 * @virtru a virtru specific implementation
 *
 * @param privateKey Crypto key to build auth token
 * @param payload Payload object to sign
 *
 */
export default async function getAuthToken(
  privateKey: CryptoKey,
  payload: JWTPayload
): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: AlgorithmName.ES256 })
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(privateKey);
}
