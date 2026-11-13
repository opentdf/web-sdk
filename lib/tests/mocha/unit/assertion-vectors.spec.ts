// Runs the shared cross-SDK assertion conformance vectors (DSPX-5520).
//
// The fixture is a byte-identical copy of xtest/vectors/assertions-phase0.json
// from opentdf/tests; update it by copying, never by editing.

import { expect } from 'chai';

import vectorFile from '../../__fixtures__/assertion-vectors-phase0.json' with { type: 'json' };
import { base64 } from '../../../src/encodings/index.js';
import { AssertionVerificationError, InvalidFileError } from '../../../src/errors.js';
import {
  assertionId,
  bindingJws,
  computeAssertionHash,
  parseAssertionWireJson,
  prepareVerificationKey,
  verifyAssertionBinding,
} from '../../../tdf3/src/assertion-verifier.js';
import * as DefaultCryptoService from '../../../tdf3/src/crypto/index.js';
import type { CryptoService } from '../../../tdf3/src/crypto/declarations.js';
import { parseManifestBytes } from '../../../tdf3/src/utils/zip-reader.js';
import { CASE_VARIANT_EXCEPTIONS_BY_PATH, MODELLED_NAMES } from '../../../tdf3/src/strict-json.js';

const cryptoService: CryptoService = DefaultCryptoService;

type VectorKey = { alg: string; publicKeyPem?: string; secretBase64?: string };
type Expectation = {
  assertionHash?: string;
  ok?: boolean;
  bindingForm?: string;
  reason?: string;
};
type Vector = {
  name: string;
  kind: 'assertion' | 'manifest' | 'binding' | 'verify';
  status: 'required' | 'proposed';
  note: string;
  input?: string;
  inputBase64?: string;
  expect: Expectation;
  selectedKey?: string;
  keySource?: 'configured' | 'payload';
  aggregateHashBase64?: string;
  legacy?: boolean;
};
type VectorFile = {
  format: string;
  modelledNames: Record<string, string[]>;
  caseVariantExceptions: Record<string, string[]>;
  keys: Record<string, VectorKey>;
  vectors: Vector[];
};

const file = vectorFile as unknown as VectorFile;

const decodeBase64 = (b64: string) => new Uint8Array(base64.decodeArrayBuffer(b64));

function inputBytes(v: Vector): Uint8Array {
  return v.input !== undefined ? new TextEncoder().encode(v.input) : decodeBase64(v.inputBase64!);
}

/** The vector's raw input as text, failing like the reader on invalid UTF-8. */
function inputText(v: Vector): string {
  if (v.input !== undefined) {
    return v.input;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(inputBytes(v));
  } catch (e) {
    throw new AssertionVerificationError(
      'invalid-json',
      'input is not valid UTF-8',
      undefined,
      e as Error
    );
  }
}

/**
 * The selected key as an application would configure it, passed to the SDK
 * unchanged even when it is deliberately unusable. The material follows the
 * entry's form (secret or PEM), not its `alg`.
 */
async function verificationKey(v: Vector) {
  const key = file.keys[v.selectedKey!];
  expect(key, `key ${v.selectedKey}`).to.exist;
  if (key.secretBase64 !== undefined) {
    const secret = decodeBase64(key.secretBase64);
    return {
      alg: key.alg,
      key: v.keySource === 'payload' ? await cryptoService.importSymmetricKey(secret) : secret,
    };
  }
  return { alg: key.alg, key: key.publicKeyPem };
}

async function run(v: Vector): Promise<Expectation> {
  try {
    switch (v.kind) {
      case 'assertion':
        // Section 3 parsing, the Section 3.3 id check, then the hash.
        return { assertionHash: await computeAssertionHash(inputText(v), cryptoService) };
      case 'manifest':
        parseManifestBytes(inputBytes(v), 'vector');
        return { ok: true };
      case 'binding':
        bindingJws(parseAssertionWireJson(inputText(v)));
        return { bindingForm: 'jws' };
      case 'verify': {
        const a = parseAssertionWireJson(inputText(v));
        let id: string | undefined;
        try {
          id = assertionId(a);
        } catch {
          id = undefined;
        }
        const key = await prepareVerificationKey(await verificationKey(v), cryptoService, id);
        await verifyAssertionBinding(
          a,
          decodeBase64(v.aggregateHashBase64 ?? ''),
          key,
          !!v.legacy,
          cryptoService,
          id
        );
        return { ok: true };
      }
      default:
        throw new Error(`unknown vector kind [${String((v as { kind: unknown }).kind)}]`);
    }
  } catch (e) {
    if (e instanceof AssertionVerificationError) {
      return { reason: e.reason };
    }
    if (v.kind === 'manifest' && e instanceof InvalidFileError) {
      // Text that is not JSON at all keeps the reader's existing error.
      return { reason: 'invalid-json' };
    }
    throw e;
  }
}

describe('shared assertion vectors (DSPX-5520)', () => {
  it('uses the expected file format', () => {
    expect(file.format).to.equal('opentdf-assertion-vectors/1');
    expect(file.vectors).to.be.an('array').that.is.not.empty;
    const names = file.vectors.map(({ name }) => name);
    expect(new Set(names).size).to.equal(names.length);
  });

  it('models the same member names and exceptions as the shared table', () => {
    expect(MODELLED_NAMES).to.deep.equal(file.modelledNames);
    expect(CASE_VARIANT_EXCEPTIONS_BY_PATH).to.deep.equal(file.caseVariantExceptions);
  });

  for (const v of file.vectors) {
    it(`${v.kind} ${v.name} [${v.status}]`, async () => {
      expect(
        (v.input === undefined) !== (v.inputBase64 === undefined),
        'exactly one of input or inputBase64'
      ).to.be.true;
      const actual = await run(v);
      if (v.status === 'proposed') {
        if (JSON.stringify(actual) !== JSON.stringify(v.expect)) {
          console.log(
            `proposed vector ${v.name}: expected ${JSON.stringify(v.expect)}, got ${JSON.stringify(actual)}`
          );
        }
        return;
      }
      expect(actual, v.note).to.deep.equal(v.expect);
    });
  }
});
