export default function arrayBufferToHex(arrayBuffer: ArrayBuffer): string | never {
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
