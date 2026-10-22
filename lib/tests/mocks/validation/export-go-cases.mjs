// Build lib first, then export the exact archive bytes used by the TS tests.
import manifestCases from '../../../dist/web/tests/mocks/validation/manifest-cases.js';
import { archive, archiveParityCases } from '../../../dist/web/tests/validation-fixtures.js';

const cases = manifestCases.map(({ name, manifest, valid }) => ({
  name,
  valid,
  bytes: archive([
    { name: '0.manifest.json', data: new TextEncoder().encode(JSON.stringify(manifest)) },
  ]),
}));
cases.push(...archiveParityCases());
console.log(
  JSON.stringify(
    cases.map(({ name, valid, bytes }) => ({
      name,
      valid,
      bytes: Buffer.from(bytes).toString('base64'),
    }))
  )
);
