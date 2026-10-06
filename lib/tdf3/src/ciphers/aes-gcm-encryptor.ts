import { Binary } from '../binary.js';
import { Algorithms } from './algorithms.js';
import {
  GCM_FIXED_FIELD_LENGTH,
  GcmIvCounter,
  MAX_GCM_INVOCATIONS_PER_FIXED_FIELD,
} from './gcm-iv-counter.js';
import {
  type AesGcmEncryptor,
  type CryptoService,
  type SymmetricKey,
} from '../crypto/declarations.js';
import { toArrayBuffer } from '../utils/index.js';
import { ConfigurationError, IvExhaustionError } from '../../../src/errors.js';

export const AES_GCM_IV_LENGTH = 12;
export const AES_GCM_TAG_LENGTH = 16;

/**
 * NIST SP 800-38D 8.3 caps the invocations of the authenticated encryption
 * function under one key at 2^32 for either IV construction. Encryptors may
 * report less -- RBG-based ones should -- but never more.
 */
export const MAX_AES_GCM_INVOCATIONS = 2 ** 32;

/**
 * A deterministic (SP 800-38D 8.2.1) encryptor layered over a caller-IV
 * `encrypt`: a fresh random fixed field per encryptor, then a counter.
 *
 * The fixed field is drawn per encryptor rather than per key because
 * `keyMiddleware` lets a caller reuse a key across encrypts, and two
 * encryptors sharing a fixed field under one key would repeat every IV.
 *
 * Each `encrypt` consumes its invocation before calling down, so an attempt
 * that fails never frees its IV for reuse.
 */
export async function deterministicAesGcmEncryptor(
  key: SymmetricKey,
  randomBytes: CryptoService['randomBytes'],
  encrypt: CryptoService['encrypt']
): Promise<AesGcmEncryptor> {
  const counter = new GcmIvCounter(await randomBytes(GCM_FIXED_FIELD_LENGTH));
  return {
    ivConstruction: 'deterministic',
    invocationLimit: MAX_GCM_INVOCATIONS_PER_FIXED_FIELD,
    async encrypt(plaintext: Uint8Array) {
      const iv = counter.next();
      const { payload, authTag } = await encrypt(
        Binary.fromArrayBuffer(toArrayBuffer(plaintext)),
        key,
        Binary.fromArrayBuffer(toArrayBuffer(iv)),
        Algorithms.AES_256_GCM
      );
      const output = new Uint8Array(payload.asArrayBuffer());
      if (authTag) {
        return { iv, ciphertext: output, tag: new Uint8Array(authTag.asArrayBuffer()) };
      }
      // `AesGcmCipher.encrypt` has always accepted a service that leaves the
      // tag on the end of the payload, so the fallback path must too.
      return {
        iv,
        ciphertext: output.slice(0, -AES_GCM_TAG_LENGTH),
        tag: output.slice(-AES_GCM_TAG_LENGTH),
      };
    },
  };
}

/**
 * Wrap `encryptor` so the writer enforces its declared limit itself and
 * refuses output it cannot record faithfully.
 *
 * The limit is read once, at wrap time, and counts attempts: a call that
 * throws has still spent whatever IV the encryptor chose for it. Lengths are
 * checked because the reader and `encryptedPayloadSize` both assume a 12-byte
 * IV prefix and a 16-byte tag suffix; anything else writes a TDF that cannot
 * be parsed back.
 */
export function guardAesGcmEncryptor(encryptor: AesGcmEncryptor): AesGcmEncryptor {
  const { ivConstruction, invocationLimit } = encryptor;
  if (
    !Number.isInteger(invocationLimit) ||
    invocationLimit < 1 ||
    invocationLimit > MAX_AES_GCM_INVOCATIONS
  ) {
    throw new ConfigurationError(
      `Invalid AES-GCM encryptor invocation limit: ${invocationLimit}; must be an integer from 1 to ${MAX_AES_GCM_INVOCATIONS}`
    );
  }
  let attempts = 0;
  return {
    ivConstruction,
    invocationLimit,
    async encrypt(plaintext: Uint8Array) {
      if (attempts >= invocationLimit) {
        throw new IvExhaustionError(
          `Exceeded the maximum of ${invocationLimit} AES-GCM invocations for one key (${ivConstruction} IVs); the output stream is incomplete`
        );
      }
      attempts += 1;
      const result = await encryptor.encrypt(plaintext);
      if (result.iv.length !== AES_GCM_IV_LENGTH) {
        throw new ConfigurationError(
          `Invalid AES-GCM IV length: ${result.iv.length}; must be exactly ${AES_GCM_IV_LENGTH} bytes`
        );
      }
      if (result.tag.length !== AES_GCM_TAG_LENGTH) {
        throw new ConfigurationError(
          `Invalid AES-GCM tag length: ${result.tag.length}; must be exactly ${AES_GCM_TAG_LENGTH} bytes`
        );
      }
      if (result.ciphertext.length !== plaintext.length) {
        throw new ConfigurationError(
          `Invalid AES-GCM ciphertext length: ${result.ciphertext.length}; must equal the ${plaintext.length} byte plaintext`
        );
      }
      return result;
    },
  };
}

/**
 * The encryptor the writer uses for `key`: the provider's own when it offers
 * one, else a deterministic encryptor over the provider's caller-IV `encrypt`.
 * Either way the result is guarded by {@link guardAesGcmEncryptor}.
 */
export async function createAesGcmEncryptorFor(
  cryptoService: CryptoService,
  key: SymmetricKey
): Promise<AesGcmEncryptor> {
  const encryptor = cryptoService.createAesGcmEncryptor
    ? await cryptoService.createAesGcmEncryptor(key)
    : await deterministicAesGcmEncryptor(
        key,
        (length) => cryptoService.randomBytes(length),
        (...args) => cryptoService.encrypt(...args)
      );
  return guardAesGcmEncryptor(encryptor);
}
