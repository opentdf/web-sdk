import { expect } from 'chai';
import { isValidTdf } from '../../../src/validation.js';
import { archive, archiveParityCases } from '../../validation-fixtures.js';
import cases from '../../mocks/validation/manifest-cases.js';

const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

async function expectInvalid(bytes: Uint8Array): Promise<void> {
  expect(await isValidTdf(bytes)).to.equal(false);
}

// Expectations were checked against OpenTDF Go SDK v0.35.0 IsValidTdf.
// No payload is present: like Go, this API validates the manifest, not ciphertext.
describe('isValidTdf Go lax-schema parity', () => {
  for (const test of cases) {
    it(test.name, async () => {
      const bytes = archive([{ name: '0.manifest.json', data: json(test.manifest) }]);
      if (!test.valid) return expectInvalid(bytes);
      expect(await isValidTdf(bytes)).to.equal(true);
      expect(await isValidTdf(new Blob([new Uint8Array(bytes)]))).to.equal(true);
    });
  }
  for (const test of archiveParityCases()) {
    it(test.name, async () => {
      if (!test.valid) return expectInvalid(test.bytes);
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
    const { fromBuffer } = await import('../../../src/seekable.js');
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
    try {
      await isValidTdf(new UnreadableBlob());
      expect.fail('Source read should fail');
    } catch (error) {
      expect(error).to.equal(failure);
    }
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
