/**
 * Copy a byte view into an ArrayBuffer with the view's exact offset and length.
 * Web Crypto's DOM typings require an ArrayBuffer-backed view in TypeScript 5.9,
 * while Uint8Array values may also be backed by SharedArrayBuffer.
 */
export function toArrayBuffer(bytes: Uint8Array | ArrayBufferView<ArrayBufferLike>): ArrayBuffer {
  const view =
    bytes instanceof Uint8Array
      ? bytes
      : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.buffer instanceof ArrayBuffer) {
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  }

  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy.buffer;
}

export function toCryptoBytes(
  bytes: ArrayBufferLike | ArrayBufferView<ArrayBufferLike>
): Uint8Array<ArrayBuffer> {
  if (bytes instanceof ArrayBuffer) {
    return new Uint8Array(bytes);
  }
  if (ArrayBuffer.isView(bytes)) {
    return new Uint8Array(toArrayBuffer(bytes));
  }
  throw new TypeError('Unsupported buffer source');
}
