import { toByteArray, fromByteArray } from 'base64-js';
import { AppIdAuthProvider, AuthProvider } from '../../../src/auth/auth.js';

export { ZipReader, readUInt64LE } from './zip-reader.js';
export { ZipWriter } from './zip-writer.js';
export { keySplit, keyMerge } from './keysplit.js';
export { streamToBuffer } from '../client/DecoratedReadableStream.js';
export * from './chunkers.js';

export type SupportedEncoding = 'hex' | 'utf8' | 'utf-8' | 'binary' | 'latin1' |'base64';

const hexSliceLookupTable = (() =>{
  const alphabet = '0123456789abcdef'
  const table = new Array(256)
  for (let i = 0; i < 16; ++i) {
    const i16 = i * 16
    for (let j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()

export function base64ToBuffer(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64).split(''), (c) => c.charCodeAt(0));
}

export function isAppIdProviderCheck(
  provider: AuthProvider | AppIdAuthProvider
): provider is AppIdAuthProvider {
  return (provider as AppIdAuthProvider)._getName !== undefined;
}
export function concatUint8(uint8Arrays: Uint8Array[]): Uint8Array {
  const newLength = uint8Arrays.reduce(
    (accumulator, currentValue) => accumulator + currentValue.length,
    0
  );
  const combinedUint8Array = new Uint8Array(newLength);

  let offset = 0;
  for (const uint8Array of uint8Arrays) {
    combinedUint8Array.set(uint8Array, offset);
    offset += uint8Array.length;
  }

  return combinedUint8Array;
}

export function readUInt32LE(uint8Array: Uint8Array, offset: number): number {
  return (
    (uint8Array[offset] |
      (uint8Array[offset + 1] << 8) |
      (uint8Array[offset + 2] << 16) |
      (uint8Array[offset + 3] << 24)) >>>
    0
  );
}

export function readUInt16LE(uint8Array: Uint8Array, offset: number): number {
  return uint8Array[offset] | (uint8Array[offset + 1] << 8);
}

export function readUInt32BE(arrayBuffer: ArrayBuffer, offset: number): number {
  const view = new DataView(arrayBuffer, offset, 4);
  return view.getUint32(0, false);
}

export function writeUInt16LE(uint8Array: Uint8Array, value: number, offset: number): void {
  uint8Array[offset] = value & 0xff;
  uint8Array[offset + 1] = (value >> 8) & 0xff;
}

export function writeUInt32LE(uint8Array: Uint8Array, value: number, offset: number): void {
  uint8Array[offset] = value & 0xff;
  uint8Array[offset + 1] = (value >> 8) & 0xff;
  uint8Array[offset + 2] = (value >> 16) & 0xff;
  uint8Array[offset + 3] = (value >> 24) & 0xff;
}

export function copyUint8Arr(
  source: Uint8Array,
  target: Uint8Array,
  targetStart: number = 0,
  sourceStart: number = 0,
  sourceEnd: number = source.length
): number {
  const length = Math.min(sourceEnd - sourceStart, target.length - targetStart);
  target.set(source.subarray(sourceStart, sourceStart + length), targetStart);
  return length;
}

// https://github.com/feross/buffer/blob/master/index.js#L1073
function hexSlice(buf: Uint8Array, start: number = 0, end: number = buf.length): string {
  const len = buf.length;

  if (!start || start < 0) start = 0;
  if (!end || end < 0 || end > len) end = len;

  let out = '';
  for (let i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]];
  }
  return out;
}

// https://github.com/feross/buffer/blob/master/index.js#L1053
function latin1Slice(buf: Uint8Array, start: number, end: number): string {
  let result = '';
  end = Math.min(buf.length, end);

  for (let i = start; i < end; ++i) {
    result += String.fromCharCode(buf[i]);
  }

  return result;
}

function base64Slice(buf: Uint8Array, start: number, end: number): string {
  if (start === 0 && end === buf.length) {
    return fromByteArray(buf);
  } else {
    return fromByteArray(buf.slice(start, end));
  }
}

// https://github.com/feross/buffer/blob/master/index.js#L483
export function buffToString(buffer: Uint8Array, encoding: SupportedEncoding = 'utf8', start = 0, end = buffer.length) {
  if (start < 0) {
    start = 0
  }

  if (end > buffer.length) {
    end = buffer.length
  }

  // Return early if start > buffer.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > buffer.length || end <= 0 || end <= start) {
    return ''
  }

  switch (encoding) {
    case 'hex':
      return hexSlice(buffer, start, end);

    case 'utf8':
    case 'utf-8':
      return utf8Slice(buffer, start, end);

    case 'latin1':
    case 'binary':
      return latin1Slice(buffer, start, end);

    case 'base64':
      return base64Slice(buffer, start, end);
  }
}

// https://github.com/feross/buffer/blob/master/index.js#L954
export function utf8Slice(buf: Uint8Array, start: number, end: number): string {
  end = Math.min(buf.length, end);
  const res: number[] = [];

  let i = start;
  while (i < end) {
    const firstByte = buf[i];
    let codePoint: number | null = null;
    let bytesPerSequence = firstByte > 0xEF
      ? 4
      : firstByte > 0xDF
        ? 3
        : firstByte > 0xBF
          ? 2
          : 1;

    if (i + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint;

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte;
          }
          break;
        case 2:
          secondByte = buf[i + 1];
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F);
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint;
            }
          }
          break;
        case 3:
          secondByte = buf[i + 1];
          thirdByte = buf[i + 2];
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F);
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint;
            }
          }
          break;
        case 4:
          secondByte = buf[i + 1];
          thirdByte = buf[i + 2];
          fourthByte = buf[i + 3];
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F);
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint;
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD;
      bytesPerSequence = 1;
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000;
      res.push((codePoint >>> 10 & 0x3FF) | 0xD800);
      codePoint = 0xDC00 | (codePoint & 0x3FF);
    }

    res.push(codePoint);
    i += bytesPerSequence;
  }

  return decodeCodePointsArray(res);
}

const MAX_ARGUMENTS_LENGTH = 0x1000;

// https://github.com/feross/buffer/blob/master/index.js#L1035
function decodeCodePointsArray(codePoints: number[]): string {
  const len = codePoints.length;
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints); // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  let res = '';
  let i = 0;
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, (i += MAX_ARGUMENTS_LENGTH))
    );
  }
  return res;
}

const INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str: string) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

export function base64ToBytes(str: string) {
  return toByteArray(base64clean(str))
}

