const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

// Use a lookup table to find the index.
let lookup: Uint8Array;

class InvalidCharacterError extends Error {
  constructor(message?: string) {
    super(message || 'Invalid character');
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// encoder
// [https://gist.github.com/999166] by [https://github.com/nignag]
function encodeFallback(input: string): string {
  let output = '';

  for (
    // initialize result and counter
    let block = 0, charCode, idx = 0, map = chars;
    // if the next input index does not exist:
    //   change the mapping table to "="
    //   check if d has no fractional digits
    input.charAt(idx | 0) || ((map = '='), idx % 1);
    // "8 - idx % 1 * 8" generates the sequence 2, 4, 6, 8
    output += map.charAt(63 & (block >> (8 - (idx % 1) * 8)))
  ) {
    charCode = input.charCodeAt((idx += 3 / 4));
    if (charCode > 0xff) {
      throw new InvalidCharacterError(`Invalid input at character ${idx}`);
    }
    block = (block << 8) | charCode;
  }
  return output;
}

/**
 * Encode array buffer to base64 string
 *
 * GitHub @niklasvh
 * Copyright (c) 2012 Niklas von Hertzen
 * MIT License
 */
export function encodeArrayBuffer(arrayBuffer: ArrayBuffer): string {
  const bytes = new Uint8Array(arrayBuffer);
  const len = bytes.length;
  let base64 = '';

  for (let i = 0; i < len; i += 3) {
    base64 += chars[bytes[i] >> 2];
    // bitshifting `undefined` results in 0, so this fills anything past
    // the end of the buffer with the appropriate value.
    base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
    base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
    base64 += chars[bytes[i + 2] & 63];
  }

  if (len % 3 === 2) {
    base64 = base64.substring(0, base64.length - 1) + '=';
  } else if (len % 3 === 1) {
    base64 = base64.substring(0, base64.length - 2) + '==';
  }

  return base64;
}

function decodeFallback(input: string): string {
  input = input.replace(/=+$/, '');
  if (input.length % 4 === 1) {
    throw new InvalidCharacterError('Invalid input.');
  }
  let output = '';
  for (
    // initialize result and counters
    let bc = 0, bs = 0, buffer, idx = 0;
    // get next character
    (buffer = input.charAt(idx++));
    // character found in table? initialize bit storage and add its ascii value;
    ~buffer &&
    ((bs = bc % 4 ? bs * 64 + buffer : buffer),
    // and if not first of each 4 characters,
    // convert the first 8 bits to one ascii character
    bc++ % 4)
      ? (output += String.fromCharCode(255 & (bs >> ((-2 * bc) & 6))))
      : 0
  ) {
    // try to find character in table (0-63, not found => -1)
    buffer = chars.indexOf(buffer);
  }
  return output;
}

function decodeArrayBuffer(base64: string): ArrayBuffer {
  if (!lookup) {
    lookup = new Uint8Array(256);
    for (let i = 0; i < 64; i++) {
      lookup[chars.charCodeAt(i)] = i;
    }
  }
  const strLength = base64.length;
  const paddingLength =
    (base64[strLength - 2] === '=' && 2) || (base64[strLength - 1] === '=' && 1) || 0;
  const binLength = (strLength >> 1) + ((strLength + 1) >> 2) - paddingLength;

  const bytes = new Uint8Array(binLength);
  for (let i = 0, p = 0; i < strLength; i += 4, p += 3) {
    const encoded1 = lookup[base64.charCodeAt(i)];
    const encoded2 = lookup[base64.charCodeAt(i + 1)];
    const encoded3 = lookup[base64.charCodeAt(i + 2)];
    const encoded4 = lookup[base64.charCodeAt(i + 3)];

    bytes[p] = (encoded1 << 2) | (encoded2 >> 4);
    bytes[p + 1] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    bytes[p + 2] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }

  return bytes.buffer;
}

const decode = decodeFallback;
const encode = encodeFallback;

export default { decode, decodeArrayBuffer, encode, encodeArrayBuffer, InvalidCharacterError };
