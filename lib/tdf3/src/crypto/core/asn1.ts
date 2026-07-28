// Generic ASN.1 / DER primitives shared by the SPKI and ML-KEM codecs.
// Definite-length BER/DER only; that is all X.509 SubjectPublicKeyInfo needs.

export function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  if (len < 0x10000) return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
  throw new Error(`ASN.1 length too large: ${len}`);
}

export function decodeLength(
  bytes: Uint8Array,
  offset: number
): { length: number; bytesConsumed: number } {
  const first = bytes[offset];
  if (first < 0x80) return { length: first, bytesConsumed: 1 };
  const numOctets = first & 0x7f;
  if (numOctets === 0 || numOctets > 3) {
    throw new Error(`Unsupported ASN.1 length octets: ${numOctets}`);
  }
  let length = 0;
  for (let i = 0; i < numOctets; i++) {
    length = (length << 8) | bytes[offset + 1 + i];
  }
  return { length, bytesConsumed: 1 + numOctets };
}

export type Tlv = {
  /** Identifier octet (tag). */
  tag: number;
  /** Index of the first content byte. */
  contentStart: number;
  /** Index one past the last content byte. */
  contentEnd: number;
  /** Start of the following TLV; equals contentEnd for definite-length values. */
  next: number;
};

/**
 * Read a single definite-length TLV (tag-length-value) starting at `offset`.
 * Throws if the declared length runs past the end of `bytes`.
 */
export function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset >= bytes.length) {
    throw new Error(`ASN.1 read past end of buffer at offset ${offset}`);
  }
  const tag = bytes[offset];
  const { length, bytesConsumed } = decodeLength(bytes, offset + 1);
  const contentStart = offset + 1 + bytesConsumed;
  const contentEnd = contentStart + length;
  if (contentEnd > bytes.length) {
    throw new Error('ASN.1 TLV length exceeds buffer size');
  }
  return { tag, contentStart, contentEnd, next: contentEnd };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
