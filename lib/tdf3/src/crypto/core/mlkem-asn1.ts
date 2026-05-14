// ASN.1 SPKI codec for ML-KEM public keys per draft-ietf-lamps-kyber-certificates
// and NIST CSRC OIDs (2.16.840.1.101.3.4.4.{1,2,3}).
//
//   SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm  AlgorithmIdentifier,  -- OID only, no parameters
//     subjectPublicKey  BIT STRING     -- raw ML-KEM encapsulation key bytes
//   }

const RAW_PUBLIC_KEY_SIZES: Record<512 | 768 | 1024, number> = {
  512: 800,
  768: 1184,
  1024: 1568,
};

const OID_VARIANT_BYTE: Record<512 | 768 | 1024, number> = { 512: 0x01, 768: 0x02, 1024: 0x03 };

const LEVEL_FROM_VARIANT_BYTE: Record<number, 512 | 768 | 1024> = {
  0x01: 512,
  0x02: 768,
  0x03: 1024,
};

// First 8 bytes of the OID's BER-encoded contents (excluding tag/length and the
// final variant byte): 2.16.840.1.101.3.4.4
const ML_KEM_OID_ARC_PREFIX = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04];

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  if (len < 0x10000) return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
  throw new Error(`ASN.1 length too large for ML-KEM SPKI: ${len}`);
}

function decodeLength(bytes: Uint8Array, offset: number): { length: number; bytesConsumed: number } {
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

export function encodeMlKemSpkiDer(rawKey: Uint8Array, level: 512 | 768 | 1024): Uint8Array {
  const expectedSize = RAW_PUBLIC_KEY_SIZES[level];
  if (rawKey.length !== expectedSize) {
    throw new Error(
      `ML-KEM-${level} raw public key must be ${expectedSize} bytes, got ${rawKey.length}`
    );
  }

  // OID: 06 09 60 86 48 01 65 03 04 04 <variant>
  const oidBytes = new Uint8Array([
    0x06,
    0x09,
    ...ML_KEM_OID_ARC_PREFIX,
    OID_VARIANT_BYTE[level],
  ]);

  // AlgorithmIdentifier ::= SEQUENCE { OID }  (no parameters per FIPS 203)
  const algIdLen = encodeLength(oidBytes.length);
  const algId = new Uint8Array(1 + algIdLen.length + oidBytes.length);
  algId[0] = 0x30;
  algId.set(algIdLen, 1);
  algId.set(oidBytes, 1 + algIdLen.length);

  // BIT STRING content: leading 0x00 (zero unused bits) || raw key
  const bitStringContent = new Uint8Array(1 + rawKey.length);
  bitStringContent[0] = 0x00;
  bitStringContent.set(rawKey, 1);
  const bitStringLen = encodeLength(bitStringContent.length);
  const bitString = new Uint8Array(1 + bitStringLen.length + bitStringContent.length);
  bitString[0] = 0x03;
  bitString.set(bitStringLen, 1);
  bitString.set(bitStringContent, 1 + bitStringLen.length);

  // Outer SubjectPublicKeyInfo SEQUENCE
  const spkiContentLen = algId.length + bitString.length;
  const spkiLen = encodeLength(spkiContentLen);
  const spki = new Uint8Array(1 + spkiLen.length + spkiContentLen);
  spki[0] = 0x30;
  spki.set(spkiLen, 1);
  spki.set(algId, 1 + spkiLen.length);
  spki.set(bitString, 1 + spkiLen.length + algId.length);
  return spki;
}

export type MlKemSpkiDecoded = { level: 512 | 768 | 1024; rawKey: Uint8Array };

export function decodeMlKemSpkiDer(der: Uint8Array): MlKemSpkiDecoded {
  if (der[0] !== 0x30) throw new Error('Invalid ML-KEM SPKI: missing outer SEQUENCE');
  let pos = 1;
  const outer = decodeLength(der, pos);
  pos += outer.bytesConsumed;
  if (pos + outer.length !== der.length) {
    throw new Error('Invalid ML-KEM SPKI: outer length does not match DER size');
  }

  if (der[pos] !== 0x30) throw new Error('Invalid ML-KEM SPKI: missing AlgorithmIdentifier');
  pos += 1;
  const algId = decodeLength(der, pos);
  pos += algId.bytesConsumed;
  const algIdEnd = pos + algId.length;

  if (der[pos] !== 0x06) throw new Error('Invalid ML-KEM SPKI: missing OID');
  pos += 1;
  const oid = decodeLength(der, pos);
  pos += oid.bytesConsumed;
  if (oid.length !== 9) {
    throw new Error(`Invalid ML-KEM SPKI: OID length ${oid.length}, expected 9`);
  }
  for (let i = 0; i < ML_KEM_OID_ARC_PREFIX.length; i++) {
    if (der[pos + i] !== ML_KEM_OID_ARC_PREFIX[i]) {
      throw new Error('Invalid ML-KEM SPKI: OID is not in id-alg-ml-kem arc');
    }
  }
  const level = LEVEL_FROM_VARIANT_BYTE[der[pos + 8]];
  if (!level) {
    throw new Error(`Invalid ML-KEM SPKI: unknown variant byte 0x${der[pos + 8].toString(16)}`);
  }
  pos += oid.length;
  if (pos !== algIdEnd) {
    throw new Error('Invalid ML-KEM SPKI: extra data inside AlgorithmIdentifier');
  }

  if (der[pos] !== 0x03) throw new Error('Invalid ML-KEM SPKI: missing BIT STRING');
  pos += 1;
  const bs = decodeLength(der, pos);
  pos += bs.bytesConsumed;
  if (der[pos] !== 0x00) throw new Error('Invalid ML-KEM SPKI: BIT STRING unused-bits must be 0');
  pos += 1;

  const rawKeyLen = bs.length - 1;
  const expectedSize = RAW_PUBLIC_KEY_SIZES[level];
  if (rawKeyLen !== expectedSize) {
    throw new Error(
      `Invalid ML-KEM SPKI: raw key length ${rawKeyLen} does not match ML-KEM-${level} (${expectedSize})`
    );
  }
  return { level, rawKey: der.slice(pos, pos + rawKeyLen) };
}

export function isMlKemSpkiDer(der: Uint8Array): boolean {
  try {
    decodeMlKemSpkiDer(der);
    return true;
  } catch {
    return false;
  }
}
