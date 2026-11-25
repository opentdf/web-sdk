import { base64 } from '../../../src/encodings/index.js';
import { encodeLength } from '../../../tdf3/src/crypto/core/asn1.js';
import { exportPublicKeyPem } from '../../../tdf3/src/crypto/core/key-format.js';
import { removePemFormatting } from '../../../tdf3/src/crypto/crypto-utils.js';
import type { CryptoService, KeyPair } from '../../../tdf3/src/crypto/declarations.js';

/**
 * Minimal DER and X.509 builders, so tests can make self-signed certificates
 * for `x5c` headers without a certificate library.
 */

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function tlv(tag: number, ...content: Uint8Array[]): Uint8Array {
  const body = concat(content);
  return concat([Uint8Array.of(tag), encodeLength(body.length), body]);
}

const sequence = (...content: Uint8Array[]) => tlv(0x30, ...content);
const set = (...content: Uint8Array[]) => tlv(0x31, ...content);

function integer(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const trimmed = bytes.subarray(start);
  return tlv(0x02, trimmed[0] & 0x80 ? concat([Uint8Array.of(0), trimmed]) : trimmed);
}

function oid(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map(Number);
  const out = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const bytes = [arc & 0x7f];
    for (let v = arc >>> 7; v; v >>>= 7) bytes.unshift((v & 0x7f) | 0x80);
    out.push(...bytes);
  }
  return tlv(0x06, Uint8Array.from(out));
}

function utcTime(d: Date): Uint8Array {
  const two = (n: number) => String(n).padStart(2, '0');
  const s = `${two(d.getUTCFullYear() % 100)}${two(d.getUTCMonth() + 1)}${two(d.getUTCDate())}${two(
    d.getUTCHours()
  )}${two(d.getUTCMinutes())}${two(d.getUTCSeconds())}Z`;
  return tlv(0x17, new TextEncoder().encode(s));
}

export const commonName = (cn: string) =>
  sequence(set(sequence(oid('2.5.4.3'), tlv(0x0c, new TextEncoder().encode(cn)))));

export { concat, integer, oid, sequence, set, tlv, utcTime };

/** The DER SubjectPublicKeyInfo of an SDK public key. */
export async function spkiOf(keyPair: KeyPair): Promise<Uint8Array> {
  return new Uint8Array(
    base64.decodeArrayBuffer(removePemFormatting(await exportPublicKeyPem(keyPair.publicKey)))
  );
}

/** The parts of a certificate; each defaults to a well-formed value. */
export type CertificateParts = {
  version?: Uint8Array;
  serial?: Uint8Array;
  signature?: Uint8Array;
  issuer?: Uint8Array;
  validity?: Uint8Array;
  subject?: Uint8Array;
  spki: Uint8Array;
  extensions?: Uint8Array;
  signatureAlgorithm?: Uint8Array;
  signatureValue?: Uint8Array;
  trailing?: Uint8Array;
};

export const sha256WithRsa = () =>
  sequence(oid('1.2.840.113549.1.1.11'), Uint8Array.of(0x05, 0x00));

/**
 * A certificate built from `parts`, base64 DER. It is not signed: the reader
 * never checks certificate signatures, so this exercises parsing alone.
 */
export function certificateFrom(parts: CertificateParts): string {
  const now = Date.now();
  const tbs = sequence(
    parts.version ?? tlv(0xa0, integer(Uint8Array.of(2))),
    parts.serial ?? integer(Uint8Array.of(1)),
    parts.signature ?? sha256WithRsa(),
    parts.issuer ?? commonName('test issuer'),
    parts.validity ??
      sequence(utcTime(new Date(now - 86_400_000)), utcTime(new Date(now + 86_400_000))),
    parts.subject ?? commonName('test subject'),
    parts.spki,
    parts.extensions ?? new Uint8Array()
  );
  return base64.encodeArrayBuffer(
    concat([
      sequence(
        tbs,
        parts.signatureAlgorithm ?? sha256WithRsa(),
        parts.signatureValue ?? tlv(0x03, Uint8Array.of(0), new Uint8Array(32))
      ),
      parts.trailing ?? new Uint8Array(),
    ])
  );
}

/**
 * A self-signed X.509 v3 certificate for `keyPair`, base64 DER as used in a
 * JWS `x5c` header.
 */
export async function selfSignedCertificate(
  cryptoService: CryptoService,
  keyPair: KeyPair,
  alg: 'RS256' | 'ES256',
  cn = 'assertion test signer'
): Promise<string> {
  const spki = await spkiOf(keyPair);
  const signatureAlgorithm =
    alg === 'RS256' ? sha256WithRsa() : sequence(oid('1.2.840.10045.4.3.2'));
  const now = Date.now();
  const tbs = sequence(
    tlv(0xa0, integer(Uint8Array.of(2))),
    integer(await cryptoService.randomBytes(8)),
    signatureAlgorithm,
    commonName(cn),
    sequence(utcTime(new Date(now - 86_400_000)), utcTime(new Date(now + 365 * 86_400_000))),
    commonName(cn),
    spki
  );
  let signature = await cryptoService.sign(tbs, keyPair.privateKey, alg);
  if (alg === 'ES256') {
    // X.509 carries ECDSA signatures as DER, not raw R || S.
    signature = sequence(integer(signature.subarray(0, 32)), integer(signature.subarray(32)));
  }
  const certificate = sequence(tbs, signatureAlgorithm, tlv(0x03, Uint8Array.of(0), signature));
  return base64.encodeArrayBuffer(certificate);
}
