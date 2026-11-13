/**
 * Public-key identities for comparing assertion verification keys (ZTDF
 * assertions contract, Section 6.2): RFC 7638 SHA-256 thumbprints of a JWK, a
 * DER SubjectPublicKeyInfo, a PEM public key, or the key in an X.509
 * certificate.
 *
 * Parsing is strict, so that every SDK rejects the same malformed input:
 * base64url must be unpadded with zero trailing bits, JWK members must be in
 * their minimal form, and certificates must have the structure of RFC 5280
 * Section 4.1 with DER encodings. Malformed input throws
 * {@link MalformedKeyError}. Certificates are only parsed: no signature,
 * chain, validity period, or extension is checked or trusted.
 *
 * Internal; not exported from the package.
 */
import { base64 } from '../../src/encodings/index.js';
import { bytesEqual, readTlv, type Tlv } from './crypto/core/asn1.js';
import type { CryptoService } from './crypto/declarations.js';

/** Key material that does not parse. The message says why. */
export class MalformedKeyError extends Error {
  override name = 'MalformedKeyError';
}

function malformed(detail: string): never {
  throw new MalformedKeyError(detail);
}

// ---------------------------------------------------------------------------
// Base64

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64URL = /^[A-Za-z0-9_-]*$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Decode unpadded base64url (RFC 7515 Section 2), or return undefined when
 * the text is padded, uses another alphabet, has an impossible length, or has
 * non-zero bits after the last whole octet.
 */
export function decodeBase64urlStrict(text: string): Uint8Array | undefined {
  const remainder = text.length % 4;
  if (!BASE64URL.test(text) || remainder === 1) {
    return undefined;
  }
  if (remainder) {
    const last = BASE64URL_ALPHABET.indexOf(text[text.length - 1]);
    if (last & (remainder === 2 ? 0x0f : 0x03)) {
      return undefined;
    }
  }
  return new Uint8Array(base64.decodeArrayBuffer(text + '='.repeat((4 - remainder) % 4)));
}

/** Decode padded standard base64, as an `x5c` entry uses, or return undefined. */
export function decodeBase64Padded(text: string): Uint8Array | undefined {
  if (!BASE64.test(text)) {
    return undefined;
  }
  // Canonical: no set bits after the last whole octet.
  const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  if (padding) {
    const last = BASE64_ALPHABET.indexOf(text[text.length - 1 - padding]);
    if (last & (padding === 2 ? 0x0f : 0x03)) {
      return undefined;
    }
  }
  return new Uint8Array(base64.decodeArrayBuffer(text));
}

// ---------------------------------------------------------------------------
// Thumbprints

/** JWK `kty` and curve names with their coordinate or key lengths in octets. */
const EC_CURVES: Array<[string, Uint8Array, number]> = [
  ['P-256', Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07), 32],
  ['P-384', Uint8Array.of(0x2b, 0x81, 0x04, 0x00, 0x22), 48],
  ['P-521', Uint8Array.of(0x2b, 0x81, 0x04, 0x00, 0x23), 66],
];
// Signature curves only: an X25519 or X448 key cannot sign a binding.
const OKP_CURVES: Array<[string, Uint8Array, number]> = [
  ['Ed25519', Uint8Array.of(0x2b, 0x65, 0x70), 32],
  ['Ed448', Uint8Array.of(0x2b, 0x65, 0x71), 57],
];

/** Short Weierstrass parameters (a = -3) of the NIST curves, for on-curve checks. */
const EC_PARAMETERS: Record<string, { p: bigint; b: bigint }> = {
  'P-256': {
    p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
    b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
  },
  'P-384': {
    p: BigInt(
      '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'
    ),
    b: BigInt(
      '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'
    ),
  },
  'P-521': {
    p: (BigInt(1) << BigInt(521)) - BigInt(1),
    b: BigInt(
      '0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'
    ),
  },
};

function toBigInt(bytes: Uint8Array): bigint {
  let hex = '0x0';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}

/** Throws unless (x, y) is a point on `crv`: y^2 = x^3 - 3x + b (mod p). */
function checkOnCurve(crv: string, xBytes: Uint8Array, yBytes: Uint8Array): void {
  const { p, b } = EC_PARAMETERS[crv];
  const x = toBigInt(xBytes);
  const y = toBigInt(yBytes);
  const mod = (v: bigint) => ((v % p) + p) % p;
  if (x >= p || y >= p || mod(y * y) !== mod(x * x * x - BigInt(3) * x + b)) {
    malformed(`EC point is not on ${crv}`);
  }
}
const RSA_ENCRYPTION = Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01);
const EC_PUBLIC_KEY = Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);

/**
 * The identity of a well-formed key whose type has no JWK form here. It never
 * equals a thumbprint, so such a key matches no selected key and no `jwk`.
 */
export const UNSUPPORTED_KEY = 'unsupported key type';

const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

const b64url = (bytes: Uint8Array) => base64.encodeArrayBuffer(bytes, true);

/** The RFC 7638 SHA-256 thumbprint, base64url, of a key's required members. */
async function thumbprint(
  members: Record<string, string>,
  cryptoService: CryptoService
): Promise<string> {
  const json = `{${Object.keys(members)
    .sort()
    .map((m) => `${JSON.stringify(m)}:${JSON.stringify(members[m])}`)
    .join(',')}}`;
  return b64url(await cryptoService.digest('SHA-256', new TextEncoder().encode(json)));
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOwn(o: object, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, name);
}

/**
 * The thumbprint of a public JWK. Throws for a symmetric or private key, a
 * `kty` or curve this SDK does not know, or members that are malformed for
 * the `kty`: not strict base64url, RSA integers with leading zero octets, or
 * curve coordinates of the wrong length.
 */
export async function jwkIdentity(jwk: unknown, cryptoService: CryptoService): Promise<string> {
  if (!isJsonObject(jwk)) {
    return malformed('jwk is not a JSON object');
  }
  const { kty } = jwk;
  if (typeof kty !== 'string') {
    return malformed('jwk has no kty');
  }
  if (kty === 'oct') {
    return malformed('jwk is a symmetric key');
  }
  if (PRIVATE_JWK_MEMBERS.some((m) => hasOwn(jwk, m))) {
    return malformed('jwk contains private key material');
  }
  const text = (name: string): string => {
    const value = jwk[name];
    return hasOwn(jwk, name) && typeof value === 'string' && value
      ? value
      : malformed(`jwk ${name} is missing or not a string`);
  };
  const octets = (name: string, length?: number): Uint8Array => {
    const decoded = decodeBase64urlStrict(text(name));
    if (!decoded?.length) {
      return malformed(`jwk ${name} is not base64url`);
    }
    if (length !== undefined && decoded.length !== length) {
      return malformed(`jwk ${name} is ${decoded.length} octets, not ${length}`);
    }
    return decoded;
  };
  const curveSize = (curves: Array<[string, Uint8Array, number]>): number => {
    const crv = text('crv');
    const curve = curves.find(([name]) => name === crv);
    return curve ? curve[2] : malformed(`jwk curve ${JSON.stringify(crv)} is not supported`);
  };
  switch (kty) {
    case 'RSA':
      for (const m of ['n', 'e']) {
        const value = octets(m);
        if (value.length > 1 && value[0] === 0) {
          malformed(`jwk ${m} has leading zero octets`);
        }
      }
      return thumbprint({ e: text('e'), kty, n: text('n') }, cryptoService);
    case 'EC': {
      const size = curveSize(EC_CURVES);
      checkOnCurve(text('crv'), octets('x', size), octets('y', size));
      return thumbprint({ crv: text('crv'), kty, x: text('x'), y: text('y') }, cryptoService);
    }
    case 'OKP':
      octets('x', curveSize(OKP_CURVES));
      return thumbprint({ crv: text('crv'), kty, x: text('x') }, cryptoService);
    default:
      return malformed(`jwk key type ${JSON.stringify(kty)} is not supported`);
  }
}

// ---------------------------------------------------------------------------
// DER

/** Reads DER TLVs in sequence from `der[offset, end)`. */
class DerReader {
  constructor(
    private readonly der: Uint8Array,
    private offset: number,
    private readonly end: number
  ) {}

  static of(der: Uint8Array): DerReader {
    return new DerReader(der, 0, der.length);
  }

  get done(): boolean {
    return this.offset >= this.end;
  }

  peekTag(): number | undefined {
    return this.done ? undefined : this.der[this.offset];
  }

  /** The next TLV, which must have `tag` (any tag when undefined). */
  read(what: string, tag?: number): Tlv {
    if (this.done) {
      return malformed(`${what} is missing`);
    }
    let tlv: Tlv;
    try {
      tlv = readTlv(this.der, this.offset);
    } catch (e) {
      return malformed(`${what} is not DER: ${(e as Error).message}`);
    }
    if ((tag !== undefined && tlv.tag !== tag) || tlv.next > this.end) {
      return malformed(`${what} is malformed`);
    }
    this.offset = tlv.next;
    return tlv;
  }

  /** A reader over the contents of `tlv`. */
  inner(tlv: Tlv): DerReader {
    return new DerReader(this.der, tlv.contentStart, tlv.contentEnd);
  }

  contents(tlv: Tlv): Uint8Array {
    return this.der.subarray(tlv.contentStart, tlv.contentEnd);
  }

  encoding(tlv: Tlv, start: number): Uint8Array {
    return this.der.subarray(start, tlv.next);
  }

  get position(): number {
    return this.offset;
  }

  finish(what: string): void {
    if (!this.done) {
      malformed(`unexpected data after ${what}`);
    }
  }
}

const SEQUENCE = 0x30;
const SET = 0x31;
const INTEGER = 0x02;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const BOOLEAN = 0x01;
const OBJECT_IDENTIFIER = 0x06;
const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;

function readOid(r: DerReader, what: string): Uint8Array {
  const oid = r.contents(r.read(what, OBJECT_IDENTIFIER));
  if (!oid.length || oid[oid.length - 1] & 0x80) {
    malformed(`${what} is not a valid OID`);
  }
  for (let i = 0; i < oid.length; i++) {
    // Each base-128 subidentifier starts after a byte without the high bit,
    // and a leading 0x80 octet would make it non-minimal.
    if (oid[i] === 0x80 && (i === 0 || !(oid[i - 1] & 0x80))) {
      malformed(`${what} is not minimally encoded`);
    }
  }
  return oid;
}

function readInteger(r: DerReader, what: string): Uint8Array {
  const value = r.contents(r.read(what, INTEGER));
  if (
    !value.length ||
    (value.length > 1 &&
      ((value[0] === 0x00 && !(value[1] & 0x80)) || (value[0] === 0xff && value[1] & 0x80)))
  ) {
    malformed(`${what} is not a DER INTEGER`);
  }
  return value;
}

/** A BIT STRING's contents after the unused-bits octet, which must be zero. */
function readBitString(r: DerReader, what: string): Uint8Array {
  const value = r.contents(r.read(what, BIT_STRING));
  if (!value.length || value[0] !== 0) {
    malformed(`${what} is not a whole-octet BIT STRING`);
  }
  return value.subarray(1);
}

/** AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL } */
function readAlgorithmIdentifier(
  r: DerReader,
  what: string
): { oid: Uint8Array; parameter?: Uint8Array; parameterTag?: number; encoding: Uint8Array } {
  const start = r.position;
  const tlv = r.read(what, SEQUENCE);
  const inner = r.inner(tlv);
  const oid = readOid(inner, `${what} OID`);
  let parameter: Uint8Array | undefined;
  let parameterTag: number | undefined;
  if (!inner.done) {
    const p = inner.read(`${what} parameters`);
    parameter = inner.contents(p);
    parameterTag = p.tag;
  }
  inner.finish(what);
  return { oid, parameter, parameterTag, encoding: r.encoding(tlv, start) };
}

/** Name ::= SEQUENCE OF SET SIZE (1..MAX) OF SEQUENCE { type OID, value ANY } */
function readName(r: DerReader, what: string): void {
  const rdns = r.inner(r.read(what, SEQUENCE));
  while (!rdns.done) {
    const set = rdns.inner(rdns.read(`${what} RDN`, SET));
    if (set.done) {
      malformed(`${what} has an empty RDN`);
    }
    while (!set.done) {
      const attribute = set.inner(set.read(`${what} attribute`, SEQUENCE));
      readOid(attribute, `${what} attribute type`);
      attribute.read(`${what} attribute value`);
      attribute.finish(`${what} attribute`);
    }
  }
}

const UTC_TIME_FORMAT = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:Z|[+-]\d{4})$/;
const GENERALIZED_TIME_FORMAT =
  /^\d{2}(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d*[1-9])?(?:Z|[+-]\d{4})$/;

function readTime(r: DerReader, what: string): void {
  const tag = r.peekTag();
  if (tag !== UTC_TIME && tag !== GENERALIZED_TIME) {
    malformed(`${what} is not a UTCTime or GeneralizedTime`);
  }
  const value = String.fromCharCode(...r.contents(r.read(what, tag)));
  const fields = (tag === UTC_TIME ? UTC_TIME_FORMAT : GENERALIZED_TIME_FORMAT).exec(value);
  const [month, day, hour, minute, second = '00'] = (fields ?? []).slice(2).map(Number);
  if (
    !fields ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    Number(second) > 59
  ) {
    malformed(`${what} is not a valid time`);
  }
}

/**
 * Extract the SubjectPublicKeyInfo from a DER X.509 certificate, checking the
 * structure RFC 5280 Section 4.1 gives it. Throws {@link MalformedKeyError}.
 */
export function certificateSpki(der: Uint8Array): Uint8Array {
  const top = DerReader.of(der);
  const certificate = top.inner(top.read('certificate', SEQUENCE));
  top.finish('certificate');

  const tbs = certificate.inner(certificate.read('tbsCertificate', SEQUENCE));
  if (tbs.peekTag() === 0xa0) {
    const explicit = tbs.inner(tbs.read('version', 0xa0));
    const version = readInteger(explicit, 'version');
    explicit.finish('version');
    if (version.length !== 1 || version[0] > 2) {
      malformed('certificate version is not v1, v2, or v3');
    }
  }
  readInteger(tbs, 'serialNumber');
  const innerSignature = readAlgorithmIdentifier(tbs, 'signature');
  readName(tbs, 'issuer');
  const validity = tbs.inner(tbs.read('validity', SEQUENCE));
  readTime(validity, 'notBefore');
  readTime(validity, 'notAfter');
  validity.finish('validity');
  readName(tbs, 'subject');
  const spkiStart = tbs.position;
  const spkiTlv = tbs.read('subjectPublicKeyInfo', SEQUENCE);
  const spki = tbs.encoding(spkiTlv, spkiStart);
  if (tbs.peekTag() === 0x81) {
    tbs.read('issuerUniqueID', 0x81);
  }
  if (tbs.peekTag() === 0x82) {
    tbs.read('subjectUniqueID', 0x82);
  }
  if (tbs.peekTag() === 0xa3) {
    const explicit = tbs.inner(tbs.read('extensions', 0xa3));
    const extensions = explicit.inner(explicit.read('extensions', SEQUENCE));
    explicit.finish('extensions');
    while (!extensions.done) {
      const extension = extensions.inner(extensions.read('extension', SEQUENCE));
      readOid(extension, 'extension OID');
      if (extension.peekTag() === BOOLEAN) {
        const critical = extension.contents(extension.read('critical', BOOLEAN));
        if (critical.length !== 1 || (critical[0] !== 0x00 && critical[0] !== 0xff)) {
          malformed('extension critical flag is not a DER BOOLEAN');
        }
      }
      extension.read('extension value', OCTET_STRING);
      extension.finish('extension');
    }
  }
  tbs.finish('tbsCertificate');

  const outerSignature = readAlgorithmIdentifier(certificate, 'signatureAlgorithm');
  if (!bytesEqual(innerSignature.encoding, outerSignature.encoding)) {
    malformed('inner and outer signature algorithms differ');
  }
  const signature = certificate.contents(certificate.read('signatureValue', BIT_STRING));
  if (!signature.length || signature[0] > 7) {
    malformed('signatureValue is not a BIT STRING');
  }
  certificate.finish('certificate');

  parseSpki(spki);
  return spki;
}

type ParsedSpki =
  | { kty: 'RSA'; n: Uint8Array; e: Uint8Array }
  | { kty: 'EC'; crv: string; x: Uint8Array; y: Uint8Array }
  | { kty: 'OKP'; crv: string; x: Uint8Array }
  | { kty: undefined };

/** SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING } */
function parseSpki(der: Uint8Array): ParsedSpki {
  const top = DerReader.of(der);
  const spki = top.inner(top.read('subjectPublicKeyInfo', SEQUENCE));
  top.finish('subjectPublicKeyInfo');
  const algorithm = readAlgorithmIdentifier(spki, 'public key algorithm');
  const key = readBitString(spki, 'subjectPublicKey');
  spki.finish('subjectPublicKeyInfo');

  if (bytesEqual(algorithm.oid, RSA_ENCRYPTION)) {
    const outer = DerReader.of(key);
    const rsa = outer.inner(outer.read('RSAPublicKey', SEQUENCE));
    outer.finish('RSAPublicKey');
    const n = readInteger(rsa, 'modulus');
    const e = readInteger(rsa, 'publicExponent');
    rsa.finish('RSAPublicKey');
    if (n[0] & 0x80 || e[0] & 0x80) {
      malformed('RSA modulus and exponent must be positive');
    }
    const minimal = (v: Uint8Array) => (v.length > 1 && v[0] === 0 ? v.subarray(1) : v);
    return { kty: 'RSA', n: minimal(n), e: minimal(e) };
  }
  if (bytesEqual(algorithm.oid, EC_PUBLIC_KEY)) {
    const curve = EC_CURVES.find(
      ([, oid]) =>
        algorithm.parameterTag === OBJECT_IDENTIFIER &&
        !!algorithm.parameter &&
        bytesEqual(oid, algorithm.parameter)
    );
    if (!curve) {
      return { kty: undefined };
    }
    const [crv, , size] = curve;
    if (key.length !== 1 + 2 * size || key[0] !== 0x04) {
      // Compressed points have no JWK form; anything else is malformed.
      if ((key[0] === 0x02 || key[0] === 0x03) && key.length === 1 + size) {
        return { kty: undefined };
      }
      return malformed('EC public key is not a point on its curve');
    }
    const x = key.subarray(1, 1 + size);
    const y = key.subarray(1 + size);
    checkOnCurve(crv, x, y);
    return { kty: 'EC', crv, x, y };
  }
  const okp = OKP_CURVES.find(([, oid]) => bytesEqual(oid, algorithm.oid));
  if (okp) {
    const [crv, , size] = okp;
    if (key.length !== size || algorithm.parameter) {
      malformed(`${crv} public key is malformed`);
    }
    return { kty: 'OKP', crv, x: key };
  }
  return { kty: undefined };
}

/** The thumbprint of a DER SubjectPublicKeyInfo, or {@link UNSUPPORTED_KEY}. */
export async function spkiIdentity(der: Uint8Array, cryptoService: CryptoService): Promise<string> {
  const key = parseSpki(der);
  switch (key.kty) {
    case 'RSA':
      return thumbprint({ e: b64url(key.e), kty: 'RSA', n: b64url(key.n) }, cryptoService);
    case 'EC':
      return thumbprint(
        { crv: key.crv, kty: 'EC', x: b64url(key.x), y: b64url(key.y) },
        cryptoService
      );
    case 'OKP':
      return thumbprint({ crv: key.crv, kty: 'OKP', x: b64url(key.x) }, cryptoService);
    default:
      return UNSUPPORTED_KEY;
  }
}

const PEM = /^\s*-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\s]*)-----END \1-----\s*$/;

/**
 * The thumbprint of a PEM `PUBLIC KEY` or of the key in a PEM `CERTIFICATE`.
 * Throws for any other PEM.
 */
export async function pemIdentity(pem: string, cryptoService: CryptoService): Promise<string> {
  const match = PEM.exec(pem);
  const der = match && decodeBase64Padded(match[2].replace(/\s+/g, ''));
  if (!match || !der) {
    return malformed('key is not a single PEM block');
  }
  switch (match[1]) {
    case 'PUBLIC KEY':
      return spkiIdentity(der, cryptoService);
    case 'CERTIFICATE':
      return spkiIdentity(certificateSpki(der), cryptoService);
    default:
      return malformed(`PEM ${match[1]} is not a public key or certificate`);
  }
}
