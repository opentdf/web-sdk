import { expect } from 'chai';

import { resolveSpecVersion } from '../../../tdf3/src/models/manifest.js';

/**
 * `schemaVersion` is the canonical name; `tdf_spec_version` is a non-aligned
 * name archival files carry at the root and under `payload`. Mirrors the Go
 * SDK's TestManifest_UnmarshalJSON_SpecVersion (opentdf/platform#4060).
 */
describe('resolveSpecVersion', () => {
  const cases: {
    name: string;
    root?: Record<string, unknown>;
    payload?: Record<string, unknown>;
    want: string | undefined;
  }[] = [
    { name: 'schemaVersion at root', root: { schemaVersion: '4.3.0' }, want: '4.3.0' },
    { name: 'tdf_spec_version at root', root: { tdf_spec_version: '4.3.0' }, want: '4.3.0' },
    {
      name: 'tdf_spec_version under payload',
      payload: { tdf_spec_version: '4.3.0' },
      want: '4.3.0',
    },
    {
      name: 'schemaVersion wins over payload tdf_spec_version',
      root: { schemaVersion: '4.3.0' },
      payload: { tdf_spec_version: '4.2.0' },
      want: '4.3.0',
    },
    {
      name: 'schemaVersion wins over root tdf_spec_version',
      root: { schemaVersion: '4.3.0', tdf_spec_version: '4.2.0' },
      want: '4.3.0',
    },
    {
      name: 'root tdf_spec_version wins over the payload copy',
      root: { tdf_spec_version: '4.3.0' },
      payload: { tdf_spec_version: '4.2.0' },
      want: '4.3.0',
    },
    {
      name: 'null root tdf_spec_version falls through to payload',
      root: { tdf_spec_version: null },
      payload: { tdf_spec_version: '4.3.0' },
      want: '4.3.0',
    },
    {
      name: 'empty schemaVersion falls through to tdf_spec_version',
      root: { schemaVersion: '' },
      payload: { tdf_spec_version: '4.3.0' },
      want: '4.3.0',
    },
    {
      name: 'non-string schemaVersion falls through to tdf_spec_version',
      root: { schemaVersion: 430, tdf_spec_version: '4.3.0' },
      want: '4.3.0',
    },
    { name: 'no version at all', want: undefined },
    { name: 'null under payload', payload: { tdf_spec_version: null }, want: undefined },
    { name: 'number under payload', payload: { tdf_spec_version: 430 }, want: undefined },
    { name: 'object under payload', payload: { tdf_spec_version: { major: 4 } }, want: undefined },
    { name: 'array at root', root: { tdf_spec_version: ['4.3.0'] }, want: undefined },
    { name: 'boolean at root', root: { schemaVersion: true }, want: undefined },
  ];

  for (const { name, root, payload, want } of cases) {
    it(name, () => {
      const manifest = {
        payload: {
          type: 'reference',
          url: '0.payload',
          protocol: 'zip',
          isEncrypted: true,
          ...payload,
        },
        ...root,
      };
      expect(resolveSpecVersion(manifest)).to.equal(want);
    });
  }

  for (const [label, manifest] of [
    ['null', null],
    ['undefined', undefined],
    ['a string', '4.3.0'],
    ['an object with a null payload', { payload: null }],
    ['an object with a string payload', { payload: 'x' }],
  ] as const) {
    it(`returns undefined, without throwing, for ${label}`, () => {
      expect(resolveSpecVersion(manifest)).to.equal(undefined);
    });
  }
});
