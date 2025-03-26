/**
 * Exposes the released version number of the `@opentdf/sdk` package
 */
export const version = '0.3.0';

/**
 * A string name used to label requests as coming from this library client.
 */
export const clientType = 'web-sdk';

/**
 * Version of the opentdf/spec this library is targeting
 */
export const tdfSpecVersion: SupportedTDFSpecVersion = '4.3.0';

export type SupportedTDFSpecVersion = '4.2.2' | '4.3.0';

export type KnownTDFSpecVersion = SupportedTDFSpecVersion;

export function isSupportedTDFSpecVersion(version: string): version is SupportedTDFSpecVersion {
  return version === '4.2.2' || version === '4.3.0';
}

export function isKnownTDFSpecVersion(version: string): version is KnownTDFSpecVersion {
  return isSupportedTDFSpecVersion(version);
}
