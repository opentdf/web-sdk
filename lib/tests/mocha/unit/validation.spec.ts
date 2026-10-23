import { expect } from 'chai';
import { ConfigurationError } from '../../../src/errors.js';
import { fromBuffer } from '../../../src/seekable.js';
import { isValidTdf, loadManifestValidator, validateTdf } from '../../../src/validation.js';
import { archive, archiveParityCases } from '../../validation-fixtures.js';
import cases, { experimentalCases } from '../../mocks/validation/manifest-cases.js';

const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

/** Asserts both APIs reject `bytes`, and returns validateTdf's reason. */
async function expectInvalid(bytes: Uint8Array): Promise<string> {
  expect(await isValidTdf(bytes)).to.equal(false);
  const result = await validateTdf(bytes);
  if (result.valid) {
    expect.fail('validateTdf reported valid');
  }
  expect(result.reason).to.be.a('string').and.not.be.empty;
  return result.reason;
}

/** Resolves to the rejection reason of `promise`; fails the test if it resolves. */
function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    (value) => expect.fail(`expected a rejection, but it resolved to ${JSON.stringify(value)}`),
    (error: unknown) => error
  );
}

/** Delegates to a real Blob, but is not one: like a Blob from another realm. */
const blobLike = (blob: Blob): Blob =>
  ({
    size: blob.size,
    type: blob.type,
    slice: (start?: number, end?: number) => blobLike(blob.slice(start, end)),
    arrayBuffer: () => blob.arrayBuffer(),
  }) as Blob;

// Copied so the bytes are ArrayBuffer-backed, as Blob and Response require.
const validTdf = () =>
  new Uint8Array(archive([{ name: '0.manifest.json', data: json(cases[0].manifest) }]));

// Expectations were checked against OpenTDF Go SDK v0.35.0 IsValidTdf.
// No payload is present: like Go, this API validates the manifest, not ciphertext.
describe('isValidTdf lax-schema validation', () => {
  for (const test of [...cases, ...experimentalCases]) {
    it(test.name, async () => {
      const bytes = archive([{ name: '0.manifest.json', data: json(test.manifest) }]);
      if (!test.valid) {
        await expectInvalid(bytes);
        return;
      }
      expect(await isValidTdf(bytes)).to.equal(true);
      expect(await isValidTdf(new Blob([new Uint8Array(bytes)]))).to.equal(true);
    });
  }
  for (const test of archiveParityCases()) {
    it(test.name, async () => {
      if (!test.valid) {
        await expectInvalid(test.bytes);
        return;
      }
      expect(await isValidTdf(test.bytes)).to.equal(true);
    });
  }
  for (const zip64 of [false, true]) {
    for (const name of ['manifest.json', '0.manifest.json']) {
      it(`accepts ${zip64 ? 'ZIP64' : 'ZIP'} with ${name}`, async () => {
        const bytes = archive([{ name, data: json(cases[0].manifest) }], zip64);
        expect(await isValidTdf(bytes)).to.equal(true);
      });
    }
  }
  it('prefers the spec manifest name when both names are present', async () => {
    const bytes = archive([
      { name: '0.manifest.json', data: json({}) },
      { name: 'manifest.json', data: json(cases[0].manifest) },
    ]);
    expect(await isValidTdf(bytes)).to.equal(true);
  });
  it('does not fall back when the preferred manifest fails schema validation', async () => {
    await expectInvalid(
      archive([
        { name: '0.manifest.json', data: json(cases[0].manifest) },
        { name: 'manifest.json', data: json({}) },
      ])
    );
  });
  for (const payloadSize of [0, 1, 28]) {
    it(`does not validate payload size ${payloadSize}`, async () => {
      expect(
        await isValidTdf(
          archive([
            { name: '0.manifest.json', data: json(cases[0].manifest) },
            { name: '0.payload', data: new Uint8Array(payloadSize) },
          ])
        )
      ).to.equal(true);
    });
  }
  it('does not verify payload checksums', async () => {
    const bytes = archive([
      { name: '0.manifest.json', data: json(cases[0].manifest) },
      { name: '0.payload', data: new Uint8Array(28) },
    ]);
    // Locate opaque payload bytes through the existing archive reader.
    const { loadTDFStream } = await import('../../../tdf3/src/tdf.js');
    const { centralDirectory } = await loadTDFStream(fromBuffer(bytes));
    const payload = centralDirectory.find(({ fileName }) => fileName === '0.payload')!;
    bytes[payload.relativeOffsetOfLocalHeader + payload.headerLength] ^= 1;
    expect(await isValidTdf(bytes)).to.equal(true);
  });
  it('propagates unexpected source read errors', async () => {
    const failure = new Error('Source is unavailable');
    class UnreadableBlob extends Blob {
      override slice(): Blob {
        throw failure;
      }
    }
    expect(await rejectionOf(isValidTdf(new UnreadableBlob()))).to.equal(failure);
    expect(await rejectionOf(validateTdf(new UnreadableBlob()))).to.equal(failure);
  });
  it('rejects invalid manifest JSON', async () => {
    await expectInvalid(
      archive([{ name: '0.manifest.json', data: new TextEncoder().encode('{') }])
    );
  });
  it('rejects a missing manifest', async () => {
    await expectInvalid(archive([{ name: '0.payload', data: new Uint8Array() }]));
  });
  it('rejects a truncated archive', async () => {
    await expectInvalid(
      archive([{ name: '0.manifest.json', data: json(cases[0].manifest) }]).slice(0, -10)
    );
  });
});

describe('validateTdf', () => {
  it('reports a valid TDF without a reason', async () => {
    expect(await validateTdf(validTdf())).to.eql({ valid: true });
  });
  it('reports why the archive is unreadable', async () => {
    const reason = await expectInvalid(new TextEncoder().encode('not a ZIP archive'));
    expect(reason).to.contain('end of central directory');
  });
  it('reports why the manifest is not JSON', async () => {
    const reason = await expectInvalid(
      archive([{ name: '0.manifest.json', data: new TextEncoder().encode('{') }])
    );
    expect(reason).to.contain('not valid JSON');
  });
  it('reports the most specific schema error', async () => {
    const manifest = structuredClone(cases[0].manifest) as { payload: { isEncrypted: unknown } };
    manifest.payload.isEncrypted = 'yes';
    const reason = await expectInvalid(
      archive([{ name: '0.manifest.json', data: json(manifest) }])
    );
    expect(reason).to.contain('lax schema');
    expect(reason).to.contain('#/payload/isEncrypted');
    expect(reason).to.contain('boolean');
  });
  it('reports a missing required property', async () => {
    const reason = await expectInvalid(archive([{ name: '0.manifest.json', data: json({}) }]));
    expect(reason).to.contain('required property "payload"');
  });
});

describe('validateTdf source types', () => {
  it('reads a Chunker', async () => {
    const reads: (number | undefined)[][] = [];
    const bytes = validTdf();
    const chunker = fromBuffer(bytes);
    const source = (start?: number, end?: number) => {
      reads.push([start, end]);
      return chunker(start, end);
    };
    expect(await isValidTdf(source)).to.equal(true);
    expect(await validateTdf(source)).to.eql({ valid: true });
    // It reads the tail first and never asks for the whole archive.
    expect(reads[0][0]).to.be.lessThan(0);
    expect(reads.every(([start]) => start !== undefined)).to.equal(true);
  });
  it('reports an invalid archive read through a Chunker', async () => {
    const result = await validateTdf(fromBuffer(new TextEncoder().encode('not a ZIP archive')));
    expect(result).to.deep.include({ valid: false });
  });
  it('propagates errors thrown by a Chunker', async () => {
    const failure = new Error('file changed while reading');
    const error = await rejectionOf(validateTdf(() => Promise.reject(failure)));
    expect(error).to.equal(failure);
  });
  it('reads a Blob-like object that is not a Blob instance', async () => {
    const source = blobLike(new Blob([validTdf()]));
    expect(source).to.not.be.instanceOf(Blob);
    expect(await isValidTdf(source)).to.equal(true);
    expect(await validateTdf(source)).to.eql({ valid: true });
  });
  for (const [name, source] of [
    ['a number[]', Array.from(validTdf())],
    ['a string', 'PK'],
    // A valid TDF's bytes: an ArrayBuffer used to pass by accident.
    ['an ArrayBuffer', validTdf().buffer],
    ['a plain object', {}],
    ['a Response', new Response(validTdf())],
    ['null', null],
    ['undefined', undefined],
  ] as const) {
    it(`rejects ${name} instead of resolving false`, async () => {
      for (const check of [isValidTdf, validateTdf]) {
        const error = await rejectionOf(check(source as unknown as Uint8Array));
        expect(error).to.be.instanceOf(ConfigurationError);
        expect((error as Error).message).to.contain('expected a Uint8Array, Blob or Chunker');
      }
    });
  }
});

describe('loadManifestValidator', () => {
  it('loads the validator', async () => {
    const { validateManifest } = await loadManifestValidator();
    expect(validateManifest(cases[0].manifest)).to.eql({ valid: true });
  });
  it('adds context when the validator fails to load', async () => {
    const cause = new TypeError('Failed to fetch dynamically imported module');
    const error = await rejectionOf(loadManifestValidator(() => Promise.reject(cause)));
    expect(error).to.be.instanceOf(Error);
    expect((error as Error).message).to.equal('validateTdf: failed to load the manifest validator');
    expect((error as Error).cause).to.equal(cause);
  });
});
