import { expect } from '@esm-bundle/chai';
import { isValidTdf, validateTdf } from '../../src/index.js';
import { archive, archiveParityCases } from '../validation-fixtures.js';
import cases, { experimentalCases } from '../mocks/validation/manifest-cases.js';

describe('isValidTdf in a browser', () => {
  for (const sourceType of ['bytes', 'Blob']) {
    for (const test of archiveParityCases()) {
      it(`${test.name} with ${sourceType}`, async () => {
        const source = sourceType === 'Blob' ? new Blob([new Uint8Array(test.bytes)]) : test.bytes;
        expect(await isValidTdf(source)).to.equal(test.valid);
      });
    }
    it(`checks the manifest corpus with ${sourceType}`, async () => {
      for (const test of [...cases, ...experimentalCases]) {
        const bytes = archive([
          {
            name: '0.manifest.json',
            data: new TextEncoder().encode(JSON.stringify(test.manifest)),
          },
        ]);
        const source = sourceType === 'Blob' ? new Blob([new Uint8Array(bytes)]) : bytes;
        expect(await isValidTdf(source), test.name).to.equal(test.valid);
      }
    });
  }

  it('reads a Blob from another realm', async () => {
    const iframe = document.createElement('iframe');
    document.body.append(iframe);
    try {
      const OtherBlob = (iframe.contentWindow as unknown as { Blob: typeof Blob }).Blob;
      const bytes = archive([
        {
          name: '0.manifest.json',
          data: new TextEncoder().encode(JSON.stringify(cases[0].manifest)),
        },
      ]);
      const source = new OtherBlob([new Uint8Array(bytes)]);
      expect(source instanceof Blob).to.equal(false);
      expect(await isValidTdf(source)).to.equal(true);
    } finally {
      iframe.remove();
    }
  });

  it('reports a reason with validateTdf', async () => {
    const result = await validateTdf(new Blob(['not a ZIP archive']));
    expect(result.valid).to.equal(false);
    expect(result.valid ? '' : result.reason).to.contain('end of central directory');
  });
});
