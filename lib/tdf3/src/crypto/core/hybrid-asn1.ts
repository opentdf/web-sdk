// Parameters and SPKI codec for the hybrid ML-KEM + ECDH composite KEMs of
// draft-ietf-lamps-pq-composite-kem-14, as the OpenTDF platform encodes them
// (lib/ocrypto, `hpqt:*` key types):
//
//   SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm  AlgorithmIdentifier,  -- composite OID only, no parameters
//     subjectPublicKey  BIT STRING     -- mlkemPK || uncompressed EC point
//   }

import { type HybridKeyAlgorithm } from '../declarations.js';
import { decodeLength, encodeLength } from './asn1.js';

export type HybridParameters = {
  /** DER content bytes of the composite algorithm OID. */
  readonly oid: Uint8Array;
  readonly mlKemLevel: 768 | 1024;
  readonly curve: 'P-256' | 'P-384';
  /** Raw ML-KEM encapsulation key size, in bytes. */
  readonly mlKemPublicKeySize: number;
  /** ML-KEM ciphertext size, in bytes. */
  readonly mlKemCiphertextSize: number;
  /** Uncompressed EC point size (0x04 || X || Y), in bytes. */
  readonly ecPointSize: number;
  /** ASCII label that the combiner appends (draft-14 §6). */
  readonly label: string;
};

export const HYBRID_PARAMETERS: Record<HybridKeyAlgorithm, HybridParameters> = {
  // id-MLKEM768-ECDH-P256: 1.3.6.1.5.5.7.6.59
  'hpqt:secp256r1-mlkem768': {
    oid: Uint8Array.of(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3b),
    mlKemLevel: 768,
    curve: 'P-256',
    mlKemPublicKeySize: 1184,
    mlKemCiphertextSize: 1088,
    ecPointSize: 65,
    label: 'MLKEM768-P256',
  },
  // id-MLKEM1024-ECDH-P384: 1.3.6.1.5.5.7.6.63
  'hpqt:secp384r1-mlkem1024': {
    oid: Uint8Array.of(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3f),
    mlKemLevel: 1024,
    curve: 'P-384',
    mlKemPublicKeySize: 1568,
    mlKemCiphertextSize: 1568,
    ecPointSize: 97,
    label: 'MLKEM1024-P384',
  },
};

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/** The hybrid algorithm whose composite OID these DER content bytes are, if any. */
export function hybridAlgorithmForOid(oid: Uint8Array): HybridKeyAlgorithm | undefined {
  return (Object.keys(HYBRID_PARAMETERS) as HybridKeyAlgorithm[]).find((algorithm) =>
    sameBytes(HYBRID_PARAMETERS[algorithm].oid, oid)
  );
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  const length = encodeLength(content.length);
  const out = new Uint8Array(1 + length.length + content.length);
  out[0] = tag;
  out.set(length, 1);
  out.set(content, 1 + length.length);
  return out;
}

export function encodeHybridSpkiDer(rawKey: Uint8Array, algorithm: HybridKeyAlgorithm): Uint8Array {
  const params = HYBRID_PARAMETERS[algorithm];
  const expectedSize = params.mlKemPublicKeySize + params.ecPointSize;
  if (rawKey.length !== expectedSize) {
    throw new Error(
      `${algorithm} raw public key must be ${expectedSize} bytes, got ${rawKey.length}`
    );
  }
  const algorithmIdentifier = tlv(0x30, tlv(0x06, params.oid));
  // BIT STRING content: leading 0x00 (zero unused bits) || raw key
  const bitString = tlv(0x03, Uint8Array.of(0x00, ...rawKey));
  return tlv(0x30, Uint8Array.of(...algorithmIdentifier, ...bitString));
}

export type HybridSpkiDecoded = { algorithm: HybridKeyAlgorithm; rawKey: Uint8Array };

export function decodeHybridSpkiDer(der: Uint8Array): HybridSpkiDecoded {
  let pos = 0;
  const expectTag = (tag: number, what: string): { start: number; end: number } => {
    if (der[pos] !== tag) throw new Error(`Invalid hybrid SPKI: missing ${what}`);
    const length = decodeLength(der, pos + 1);
    const start = pos + 1 + length.bytesConsumed;
    return { start, end: start + length.length };
  };
  const outer = expectTag(0x30, 'outer SEQUENCE');
  if (outer.end !== der.length) {
    throw new Error('Invalid hybrid SPKI: outer length does not match DER size');
  }
  pos = outer.start;
  const algorithmIdentifier = expectTag(0x30, 'AlgorithmIdentifier');
  pos = algorithmIdentifier.start;
  const oid = expectTag(0x06, 'OID');
  // The composite OIDs take no parameters.
  if (oid.end !== algorithmIdentifier.end) {
    throw new Error('Invalid hybrid SPKI: unexpected AlgorithmIdentifier parameters');
  }
  const algorithm = hybridAlgorithmForOid(der.subarray(oid.start, oid.end));
  if (!algorithm) throw new Error('Invalid hybrid SPKI: not a supported composite KEM OID');
  pos = algorithmIdentifier.end;
  const bitString = expectTag(0x03, 'BIT STRING');
  if (bitString.end !== der.length || der[bitString.start] !== 0x00) {
    throw new Error('Invalid hybrid SPKI: malformed BIT STRING');
  }
  const rawKey = der.slice(bitString.start + 1, bitString.end);
  const params = HYBRID_PARAMETERS[algorithm];
  if (rawKey.length !== params.mlKemPublicKeySize + params.ecPointSize) {
    throw new Error(
      `Invalid hybrid SPKI: raw key length ${rawKey.length} does not match ${algorithm}`
    );
  }
  return { algorithm, rawKey };
}
