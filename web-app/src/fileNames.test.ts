import { PUBLIC_KEY_ALGORITHMS } from '@opentdf/sdk';
import { describe, expect, it, vi } from 'vitest';
import {
  actualWrapQualifier,
  algorithmSlug,
  decryptedFileExtension,
  decryptedFileName,
  expectedKaoType,
  parseEncryptedFileName,
} from './fileNames.js';

// The full KasPublicKeyAlgorithm union. Kept explicit rather than imported so
// that adding a member to the SDK shows up here as a missing case instead of
// silently widening the table.
const ALL_ALGORITHMS = [
  'ec:secp256r1',
  'ec:secp384r1',
  'ec:secp521r1',
  'rsa:2048',
  'rsa:4096',
  'mlkem:768',
  'mlkem:1024',
] as const;

// ENCRYPTED_FILE_NAME builds its qualifier alternation from PUBLIC_KEY_ALGORITHMS,
// so the table above has to stay in step with the SDK or the cases below stop
// covering what the parser actually accepts.
it('covers every algorithm the SDK exposes', () => {
  expect([...ALL_ALGORITHMS]).toEqual([...PUBLIC_KEY_ALGORITHMS]);
});

describe('algorithmSlug', () => {
  it.each([
    ['ec:secp256r1', 'ecsecp256r1'],
    ['rsa:2048', 'rsa2048'],
    ['mlkem:768', 'mlkem768'],
    ['mlkem:1024', 'mlkem1024'],
  ] as const)('%s -> %s', (algorithm, expected) => {
    expect(algorithmSlug(algorithm)).toBe(expected);
  });

  // decryptedFileName concatenates the slug into a name that decrypt has to
  // re-parse, so every slug must be one ENCRYPTED_FILE_NAME's qualifier group
  // recognises -- including the three the dropdown offers but no test names.
  it('produces a slug the file name parser can round-trip, for every algorithm', () => {
    for (const algorithm of ALL_ALGORITHMS) {
      const slug = algorithmSlug(algorithm);
      expect(slug, `${algorithm} slug must be qualifier-safe`).toMatch(/^\w+$/);
      expect(parseEncryptedFileName(`README.md-${slug}.tdf`)).toEqual({
        base: 'README',
        extension: 'md',
        wrapQualifier: `-${slug}`,
      });
    }
  });
});

describe('expectedKaoType', () => {
  it.each([
    ['ec:secp256r1', 'ec-wrapped'],
    ['ec:secp521r1', 'ec-wrapped'],
    ['rsa:2048', 'wrapped'],
    ['rsa:4096', 'wrapped'],
    ['mlkem:768', 'mlkem-wrapped'],
    ['mlkem:1024', 'mlkem-wrapped'],
  ] as const)('%s -> %s', (algorithm, expected) => {
    expect(expectedKaoType(algorithm)).toBe(expected);
  });
});

describe('actualWrapQualifier', () => {
  it.each([
    ['wrapped', 'r1', '-kao=rsa-kid=r1'],
    ['ec-wrapped', 'e1', '-kao=ec-kid=e1'],
    ['mlkem-wrapped', 'mlkem768', '-kao=mlkem-kid=mlkem768'],
    ['remote', 'r1', '-kao=remote-kid=r1'],
    // kaoMetadataFrom substitutes this when the key access object has no kid.
    // Parens and a space cannot survive as a qualifier, so the kid is dropped
    // whole rather than scrubbed into something that looks real.
    ['wrapped', '(no kid)', '-kao=rsa'],
    ['ec-wrapped', 'kas-1.example', '-kao=ec'],
    ['wrapped', '', '-kao=rsa'],
  ] as const)('%s / %s -> %s', (kaoType, kid, expected) => {
    expect(actualWrapQualifier(kaoType, kid)).toBe(expected);
  });

  // Same contract as the algorithmSlug round-trip above: whatever we append on
  // encrypt, decrypt has to be able to read back off the container name.
  it('produces a qualifier the file name parser can round-trip', () => {
    for (const kaoType of ['remote', 'wrapped', 'ec-wrapped', 'mlkem-wrapped'] as const) {
      for (const kid of ['e1', 'r1', 'mlkem768', '(no kid)']) {
        const qualifier = actualWrapQualifier(kaoType, kid);
        expect(parseEncryptedFileName(`README.md${qualifier}.tdf`)).toEqual({
          base: 'README',
          extension: 'md',
          wrapQualifier: qualifier,
        });
      }
    }
  });
});

describe('parseEncryptedFileName', () => {
  it.each([
    // [input, base, extension, wrapQualifier]
    ['README.md.tdf', 'README', 'md', ''],
    ['README.md.ztdf', 'README', 'md', ''],
    ['README.md-mlkem768.tdf', 'README', 'md', '-mlkem768'],
    ['README.md-ecsecp256r1.tdf', 'README', 'md', '-ecsecp256r1'],
    ['README.md-mlkem768.ztdf', 'README', 'md', '-mlkem768'],
    // The mismatch qualifier, for when the KAS ignored the algorithm we asked
    // for. Both tokens carry an `=`, which the extension group cannot match.
    ['README.md-kao=rsa-kid=r1.tdf', 'README', 'md', '-kao=rsa-kid=r1'],
    ['README.md-kao=ec-kid=e1.tdf', 'README', 'md', '-kao=ec-kid=e1'],
    ['README.md-kao=rsa.tdf', 'README', 'md', '-kao=rsa'],
    ['archive.tar.gz-kao=ec-kid=e1.ztdf', 'archive.tar', 'gz', '-kao=ec-kid=e1'],
    ['file.foo-bar-kao=ec-kid=e1.tdf', 'file', 'foo-bar', '-kao=ec-kid=e1'],
    // Chrome and Safari insert a counter when the name is already taken. It
    // must land in the counter group, not be mistaken for a wrap qualifier.
    ['README.md-mlkem768-1.tdf', 'README', 'md', '-mlkem768'],
    ['README.md-mlkem768 (1).tdf', 'README', 'md', '-mlkem768'],
    ['README.md-kao=ec-kid=e1 (1).tdf', 'README', 'md', '-kao=ec-kid=e1'],
    ['README.md-kao=ec-kid=e1-1.tdf', 'README', 'md', '-kao=ec-kid=e1'],
    ['README.md-1.tdf', 'README', 'md', ''],
    ['README.md (2).tdf', 'README', 'md', ''],
    // Only the last dot-segment before the qualifier counts as the extension.
    ['archive.tar.gz-mlkem768.tdf', 'archive.tar', 'gz', '-mlkem768'],
    ['my file.md-mlkem768.tdf', 'my file', 'md', '-mlkem768'],
    // A hyphen in the extension is not a wrap qualifier. Only slugs we emit are.
    ['file.foo-bar-mlkem768.tdf', 'file', 'foo-bar', '-mlkem768'],
    ['file.foo-bar.tdf', 'file', 'foo-bar', ''],
    // A slug-shaped extension is read as the extension, because the qualifier
    // group only gets what the extension leaves and the extension needs at least
    // one character. `file.mlkem768` is the likelier source name anyway.
    ['file.mlkem768.tdf', 'file', 'mlkem768', ''],
    // Re-encrypting a decrypted file: the `=` in the rewrap qualifier survives.
    [
      'README-mlkem768-rwk-p=mlkem1024.decrypted.md-mlkem768.tdf',
      'README-mlkem768-rwk-p=mlkem1024.decrypted',
      'md',
      '-mlkem768',
    ],
  ])('parses %s', (input, base, extension, wrapQualifier) => {
    expect(parseEncryptedFileName(input)).toEqual({ base, extension, wrapQualifier });
  });

  it.each([
    ['README.md', 'no container extension'],
    ['Makefile-mlkem768.tdf', 'no inner extension to recover'],
    ['sample.tdf', 'no inner extension to recover'],
    ['README.md-mlkem768.TDF', 'container extension is matched case-sensitively'],
    ['random-bytes-1048576-bytes-mlkem768.tdf', "the app's own random-source name"],
  ])('returns undefined for %s (%s)', (input) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(parseEncryptedFileName(input)).toBeUndefined();
    expect(warn).toHaveBeenCalledOnce();
    warn.mockRestore();
  });

  // Documents a known limitation rather than endorsing it: the counter
  // alternative claims an all-digit token that the qualifier group has already
  // declined. Unreachable, since every slug in PUBLIC_KEY_ALGORITHMS starts with
  // a letter, and the assertion above keeps that true.
  it('mistakes an all-digit wrap qualifier for a browser counter', () => {
    expect(parseEncryptedFileName('README.md-2048.tdf')).toEqual({
      base: 'README',
      extension: 'md',
      wrapQualifier: '',
    });
  });

  // Why actualWrapQualifier exists. A bare kid is not an algorithm slug, so the
  // extension group -- which allows hyphens -- swallows it, and the decrypted
  // name inherits the damage. Pinned so the reason survives the fix.
  it.each(['e1', 'r1'])('swallows a bare `%s` kid into the extension', (kid) => {
    expect(parseEncryptedFileName(`README.md-${kid}.tdf`)).toEqual({
      base: 'README',
      extension: `md-${kid}`,
      wrapQualifier: '',
    });
  });
});

describe('decryptedFileName', () => {
  it('carries the wrap qualifier through and appends the rewrap mechanism', () => {
    expect(decryptedFileName('README.md-mlkem768.tdf', 'mlkem:1024')).toBe(
      'README-mlkem768-rwk-p=mlkem1024.decrypted.md'
    );
  });

  it('records the rewrap leg even when the container carries no wrap qualifier', () => {
    expect(decryptedFileName('README.md.tdf', 'rsa:2048')).toBe(
      'README-rwk-p=rsa2048.decrypted.md'
    );
  });

  // The reviewer's regression case: an EC or RSA kid in the name must not cost
  // the original extension. `README.md-r1.tdf` used to decrypt to
  // `README-rwk-p=mlkem768.decrypted.md-r1`.
  it.each([
    ['README.md-kao=rsa-kid=r1.tdf', 'README-kao=rsa-kid=r1-rwk-p=mlkem768.decrypted.md'],
    ['README.md-kao=ec-kid=e1.tdf', 'README-kao=ec-kid=e1-rwk-p=mlkem768.decrypted.md'],
    ['README.md-kao=rsa.tdf', 'README-kao=rsa-rwk-p=mlkem768.decrypted.md'],
  ])('carries the mismatch qualifier through and keeps the extension: %s', (input, expected) => {
    expect(decryptedFileName(input, 'mlkem:768')).toBe(expected);
  });

  it('keeps a hyphenated extension whole', () => {
    expect(decryptedFileName('file.foo-bar-mlkem768.tdf', 'mlkem:1024')).toBe(
      'file-mlkem768-rwk-p=mlkem1024.decrypted.foo-bar'
    );
  });

  it('drops a browser-inserted counter rather than treating it as a qualifier', () => {
    expect(decryptedFileName('README.md-mlkem768 (1).tdf', 'rsa:2048')).toBe(
      'README-mlkem768-rwk-p=rsa2048.decrypted.md'
    );
  });

  it('falls back to suffixing the whole name when it cannot be parsed', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(decryptedFileName('sample.tdf', 'mlkem:768')).toBe(
      'sample.tdf-rwk-p=mlkem768.decrypted'
    );
    warn.mockRestore();
  });
});

describe('decryptedFileExtension', () => {
  it('recovers the original extension', () => {
    expect(decryptedFileExtension('README.md-mlkem768.tdf')).toBe('md');
  });

  it('recovers the original extension past a mismatch qualifier', () => {
    expect(decryptedFileExtension('README.md-kao=rsa-kid=r1.tdf')).toBe('md');
  });

  // The picker's accept filter has to match the name decryptedFileName offers
  // for the same input, or the Save As dialog rejects its own suggestion.
  it.each([
    'README.md-mlkem768.tdf',
    'README.md.tdf',
    'sample.tdf',
    'Makefile-mlkem768.tdf',
    'README.md-kao=rsa-kid=r1.tdf',
    'README.md-kao=ec.tdf',
  ])('agrees with the suggested name for %s', (input) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const suggested = decryptedFileName(input, 'rsa:2048');
    expect(suggested.endsWith(`.${decryptedFileExtension(input)}`)).toBe(true);
    warn.mockRestore();
  });

  it('falls back to `decrypted`, matching the unparseable-name suffix', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(decryptedFileExtension('sample.tdf')).toBe('decrypted');
    warn.mockRestore();
  });
});
