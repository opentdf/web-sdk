import { expect } from '@esm-bundle/chai';
import { isValidTdf } from '../../src/index.js';
import { archive, archiveParityCases } from '../validation-fixtures.js';
import cases from '../mocks/validation/manifest-cases.js';

describe('isValidTdf in a browser', () => {
  for (const sourceType of ['bytes', 'Blob']) {
    for (const test of archiveParityCases()) {
      it(`${test.name} with ${sourceType}`, async () => {
        const source = sourceType === 'Blob' ? new Blob([new Uint8Array(test.bytes)]) : test.bytes;
        expect(await isValidTdf(source)).to.equal(test.valid);
      });
    }
    it(`matches the Go manifest corpus with ${sourceType}`, async () => {
      for (const test of cases) {
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
});
