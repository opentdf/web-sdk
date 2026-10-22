import { expect } from '@esm-bundle/chai';
import { validateTdf, InvalidFileError } from '../../src/index.js';
import { archive } from '../validation-fixtures.js';

describe('validateTdf in a browser', () => {
  for (const sourceType of ['bytes', 'Blob']) {
    it(`matches the Go manifest corpus with ${sourceType}`, async () => {
      const response = await fetch(
        new URL('../mocks/validation/manifest-cases.json', import.meta.url)
      );
      expect(response.ok).to.equal(true);
      const cases = (await response.json()) as {
        name: string;
        manifest: unknown;
        valid: boolean;
      }[];
      for (const test of cases) {
        const bytes = archive([
          {
            name: '0.manifest.json',
            data: new TextEncoder().encode(JSON.stringify(test.manifest)),
          },
        ]);
        const source = sourceType === 'Blob' ? new Blob([new Uint8Array(bytes)]) : bytes;
        try {
          const manifest = await validateTdf(source);
          expect(test.valid, test.name).to.equal(true);
          expect(manifest, test.name).to.deep.equal(test.manifest);
        } catch (error) {
          expect(test.valid, test.name).to.equal(false);
          expect(error, test.name).to.be.instanceOf(InvalidFileError);
        }
      }
    });
  }
});
