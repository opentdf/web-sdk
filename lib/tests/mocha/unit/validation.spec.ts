import { expect } from 'chai';
import { readFileSync } from 'node:fs';
import { validateTdf } from '../../../src/validation.js';
import { InvalidFileError } from '../../../src/errors.js';
import { archive } from '../../validation-fixtures.js';

const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const cases = JSON.parse(readFileSync('tests/mocks/validation/manifest-cases.json', 'utf8')) as {
  name: string;
  manifest: unknown;
  valid: boolean;
}[];

async function rejects(bytes: Uint8Array): Promise<void> {
  try {
    await validateTdf(bytes);
    expect.fail('Validation should reject this archive or manifest');
  } catch (error) {
    expect(error).to.be.instanceOf(InvalidFileError);
  }
}

// Expectations were checked against OpenTDF Go SDK v0.35.0 IsValidTdf.
// No payload is present: like Go, this API validates the manifest, not ciphertext.
describe('validateTdf Go lax-schema parity', () => {
  for (const test of cases) {
    it(test.name, async () => {
      const bytes = archive([{ name: '0.manifest.json', data: json(test.manifest) }]);
      if (!test.valid) return rejects(bytes);
      expect(await validateTdf(bytes)).to.deep.equal(test.manifest);
      expect(await validateTdf(new Blob([new Uint8Array(bytes)]))).to.deep.equal(test.manifest);
    });
  }
  for (const zip64 of [false, true]) {
    for (const name of ['manifest.json', '0.manifest.json']) {
      it(`accepts ${zip64 ? 'ZIP64' : 'ZIP'} with ${name}`, async () => {
        const bytes = archive([{ name, data: json(cases[0].manifest) }], zip64);
        expect(await validateTdf(bytes)).to.deep.equal(cases[0].manifest);
      });
    }
  }
  it('prefers the spec manifest name when both names are present', async () => {
    const bytes = archive([
      { name: '0.manifest.json', data: json({}) },
      { name: 'manifest.json', data: json(cases[0].manifest) },
    ]);
    expect(await validateTdf(bytes)).to.deep.equal(cases[0].manifest);
  });
  it('does not fall back when the preferred manifest fails schema validation', async () => {
    await rejects(
      archive([
        { name: '0.manifest.json', data: json(cases[0].manifest) },
        { name: 'manifest.json', data: json({}) },
      ])
    );
  });
  for (const payloadSize of [0, 1, 28]) {
    it(`does not validate payload size ${payloadSize}`, async () => {
      expect(
        await validateTdf(
          archive([
            { name: '0.manifest.json', data: json(cases[0].manifest) },
            { name: '0.payload', data: new Uint8Array(payloadSize) },
          ])
        )
      ).to.deep.equal(cases[0].manifest);
    });
  }
  it('does not verify payload checksums', async () => {
    const bytes = archive([
      { name: '0.manifest.json', data: json(cases[0].manifest) },
      { name: '0.payload', data: new Uint8Array(28) },
    ]);
    // Locate opaque payload bytes through the existing archive reader.
    const { loadTDFStream } = await import('../../../tdf3/src/tdf.js');
    const { fromBuffer } = await import('../../../src/seekable.js');
    const { centralDirectory } = await loadTDFStream(fromBuffer(bytes));
    const payload = centralDirectory.find(({ fileName }) => fileName === '0.payload')!;
    bytes[payload.relativeOffsetOfLocalHeader + payload.headerLength] ^= 1;
    expect(await validateTdf(bytes)).to.deep.equal(cases[0].manifest);
  });
  it('rejects invalid manifest JSON', async () => {
    await rejects(archive([{ name: '0.manifest.json', data: new TextEncoder().encode('{') }]));
  });
  it('rejects a missing manifest', async () => {
    await rejects(archive([{ name: '0.payload', data: new Uint8Array() }]));
  });
  it('rejects a truncated archive', async () => {
    await rejects(
      archive([{ name: '0.manifest.json', data: json(cases[0].manifest) }]).slice(0, -10)
    );
  });
});
