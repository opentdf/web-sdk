/**
 * Helpers for deciding whether a cached access token is still fresh, using the
 * JWT `exp` claim (or an OAuth `expires_in`) rather than a network round trip.
 */

/**
 * Decode a JWT's exp claim without verifying the signature.
 * Returns the expiration time in seconds since epoch, or undefined if not present.
 */
export function getJwtExpiration(token: string): number | undefined {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return undefined;
    // Base64url decode the payload
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    const decoded = JSON.parse(atob(padded));
    return typeof decoded.exp === 'number' ? decoded.exp : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Compute the absolute expiry (seconds since epoch) for a token response.
 * Prefers `expires_in` from the token response, falls back to the JWT `exp` claim.
 */
export function resolveTokenExpiry(accessToken: string, expiresIn?: number): number | undefined {
  if (typeof expiresIn === 'number') {
    return Date.now() / 1000 + expiresIn;
  }
  return getJwtExpiration(accessToken);
}

export function isTokenExpired(expiry: number | undefined, bufferSeconds = 30): boolean {
  if (expiry === undefined) return true;
  return Date.now() / 1000 >= expiry - bufferSeconds;
}
