export default function hexToArrayBuffer(hexString: string): ArrayBuffer | never {
  if (typeof hexString !== 'string') {
    throw new TypeError('Expected input of hexString to be a String');
  }

  if (hexString.length % 2 !== 0) {
    throw new RangeError('Expected string to be an even number of characters');
  }

  const byteArray = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    byteArray[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
  }

  return byteArray.buffer;
}
