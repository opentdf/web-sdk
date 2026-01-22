import type { CryptoService } from './declarations.js';

let cachedSalt: Uint8Array | null = null;

/**
 * Get the ZTDF salt (SHA-256 of "TDF").
 * Lazily computed on first call and cached thereafter.
 */
export async function getZtdfSalt(cryptoService: CryptoService): Promise<Uint8Array> {
  if (cachedSalt) {
    return cachedSalt;
  }

  const encoder = new TextEncoder();
  const data = encoder.encode('TDF');

  cachedSalt = await cryptoService.digest('SHA-256', data);
  return cachedSalt;
}
