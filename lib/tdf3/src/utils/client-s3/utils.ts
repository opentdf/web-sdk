export const toUint8Array = (data: string | ArrayBuffer | ArrayBufferView): Uint8Array => {
  if (typeof data === "string") {
    return Buffer.from(data, 'utf8');
  }

  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
  }

  return new Uint8Array(data);
};
