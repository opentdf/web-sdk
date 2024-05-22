import { base64 } from '../encodings/index.js';
import { pemCertToCrypto, pemPublicToCrypto } from './raw.js';

export function addNewLines(str: string): string {
  if (!str) {
    return str;
  }
  let inputString = str;
  let finalString = '';
  while (inputString.length > 0) {
    finalString += inputString.substring(0, 64) + '\r\n';
    inputString = inputString.substring(64);
  }
  return finalString;
}

export async function cryptoPublicToPem(publicKey: CryptoKey): Promise<string> {
  if (publicKey.type !== 'public') {
    throw new TypeError('Incorrect key type');
  }

  const exportedPublicKey = await crypto.subtle.exportKey('spki', publicKey);
  const b64 = base64.encodeArrayBuffer(exportedPublicKey);
  const pem = addNewLines(b64);
  return `-----BEGIN PUBLIC KEY-----\r\n${pem}-----END PUBLIC KEY-----`;
}

export async function pemToCryptoPublicKey(pem: string): Promise<CryptoKey> {
  if (/-----BEGIN PUBLIC KEY-----/.test(pem)) {
    return pemPublicToCrypto(pem);
  } else if (/-----BEGIN CERTIFICATE-----/.test(pem)) {
    return pemCertToCrypto(pem);
  }
  throw new Error('unsupported pem type');
}
