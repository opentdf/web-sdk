import { InvalidCharacterError } from './base64.js';

export function encode(str: string): string {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    const s = str.charCodeAt(i).toString(16);
    if (s.length < 2) {
      hex += '0' + s;
    } else if (s.length > 2) {
      throw new InvalidCharacterError(`invalid input at char ${i} == [${hex.substring(i, i + 1)}]`);
    } else {
      hex += `${s}`;
    }
  }
  return hex;
}

export function decode(hex: string): string {
  if (hex.length & 1) {
    throw new InvalidCharacterError('invalid input.');
  }
  let str = '';
  for (let i = 0; i < hex.length; i += 2) {
    const b = parseInt(hex.substring(i, i + 2), 16);
    if (isNaN(b)) {
      throw new InvalidCharacterError(`invalid input at char ${i} == [${hex.substring(i, i + 2)}]`);
    }
    str += String.fromCharCode(b);
  }
  return str;
}

export function decodeArrayBuffer(hex: string): ArrayBuffer | never {
  const binLength = hex.length >> 1; // 1 byte per 2 characters
  if (hex.length & 1) {
    throw new InvalidCharacterError('invalid input.');
  }
  const bytes = new Uint8Array(binLength);
  for (let i = 0; i < hex.length; i += 2) {
    const b = parseInt(hex.substring(i, i + 2), 16);
    if (isNaN(b)) {
      throw new InvalidCharacterError(`invalid input at char ${i} == [${hex.substring(i, i + 2)}]`);
    }
    bytes[i >> 1] = b;
  }
  return bytes.buffer;
}

export function encodeArrayBuffer(arrayBuffer: ArrayBuffer): string | never {
  if (typeof arrayBuffer !== 'object') {
    throw new TypeError('Expected input to be an ArrayBuffer Object');
  }

  const byteArray = new Uint8Array(arrayBuffer);
  let hexString = '';
  let nextHexByte;

  for (let i = 0; i < byteArray.byteLength; i++) {
    nextHexByte = byteArray[i].toString(16);

    if (nextHexByte.length < 2) {
      nextHexByte = '0' + nextHexByte;
    }

    hexString += nextHexByte;
  }

  return hexString;
}
