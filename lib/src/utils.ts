import { calculateJwkThumbprint, JWK } from 'jose';

export function isBrowser() {
  return typeof window !== 'undefined'; // eslint-disable-line
}

export const isFirefox = (): boolean => isBrowser() && 'InstallTrigger' in window;

export const rstrip = (str: string, suffix = ' '): string => {
  while (str && suffix && str.endsWith(suffix)) {
    str = str.slice(0, -suffix.length);
  }
  return str;
};

export async function sameKeys(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const e = async (k: CryptoKey) => window.crypto.subtle.exportKey('jwk', k);
  const [aE, bE]: JsonWebKey[] = await Promise.all([e(a), e(b)]);
  return calculateJwkThumbprint(aE as JWK) === calculateJwkThumbprint(bE as JWK);
}
