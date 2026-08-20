import {
  type KasPublicKeyAlgorithm,
  type KeyAccessType,
  PUBLIC_KEY_ALGORITHMS,
} from '@opentdf/sdk';

/**
 * `mlkem:768` -> `mlkem768`. Colons are legal in a file name but awkward on
 * Windows and in shell paths. For ML-KEM the slug happens to equal the KAS kid
 * (`mlkem:768` -> kid `mlkem768`); EC and RSA kids are unrelated (`e1`, `r1`).
 *
 * Every member of KasPublicKeyAlgorithm has exactly one colon and is otherwise
 * alphanumeric, so a non-global replace is enough today; a hybrid identifier
 * such as `ec:secp256r1+mlkem:768` would need `replaceAll`.
 */
export function algorithmSlug(algorithm: KasPublicKeyAlgorithm): string {
  return algorithm.replace(':', '');
}

/**
 * The key access object type the KAS should produce for a requested wrap
 * algorithm. Used to detect the case where it produced something else.
 */
export function expectedKaoType(algorithm: KasPublicKeyAlgorithm): KeyAccessType {
  if (algorithm.startsWith('mlkem:')) {
    return 'mlkem-wrapped';
  }
  return algorithm.startsWith('ec:') ? 'ec-wrapped' : 'wrapped';
}

/**
 * The coarse inverse of {@link expectedKaoType}. Deliberately coarse: a key
 * access type names the family but not the curve or modulus size, so there is
 * no honest way to recover a full algorithm slug from one.
 */
const KAO_TYPE_SLUG: Record<KeyAccessType, string> = {
  remote: 'remote',
  wrapped: 'rsa',
  'ec-wrapped': 'ec',
  'mlkem-wrapped': 'mlkem',
};

/**
 * Names what actually wrapped the DEK, for the case where that is not what we
 * asked for. Never emit a bare kid here: EC and RSA kids (`e1`, `r1`) are not
 * algorithm slugs, so `README.md-e1.tdf` parses with `md-e1` as its extension
 * and decrypt then hands back `README-rwk-p=….decrypted.md-e1`.
 *
 * The kid is dropped, not mangled, when it holds anything a qualifier cannot
 * carry -- including the `(no kid)` placeholder the caller substitutes for an
 * absent one. A half-scrubbed kid would be worse than none: the panel shows the
 * real value either way, and a name should not claim a kid nobody can look up.
 */
export function actualWrapQualifier(kaoType: KeyAccessType, kid: string): string {
  const kidToken = /^\w+$/.test(kid) ? `-kid=${kid}` : '';
  return `-kao=${KAO_TYPE_SLUG[kaoType]}${kidToken}`;
}

// Longest first so a slug that is a prefix of another cannot win and strand the
// rest of the name. Nothing in the current list overlaps; this is insurance for
// whatever gets added next.
const ALGORITHM_SLUGS = PUBLIC_KEY_ALGORITHMS.map(algorithmSlug).sort(
  (a, b) => b.length - a.length
);

// Groups: 1 file 'name' bit
// 2: original file extension. Lazy, and allows `-`, so that a hyphenated
//    extension is kept whole: without both, `file.foo-bar-mlkem768.tdf` parses as
//    extension `foo` and the decrypted name silently loses the `-bar`.
// 3: the wrap qualifier we appended on encrypt, e.g. `-mlkem768`, or the
//    `-kao=…-kid=…` pair {@link actualWrapQualifier} emits when the KAS did not
//    use the algorithm we asked for. Restricted to tokens we actually emit,
//    which is what lets group 2 tell `-bar` (part of the extension) apart from
//    `-mlkem768` (not). The `kao=`/`kid=` tokens need no such help: group 2
//    cannot match an `=`, so they can never be read as part of an extension.
//    Repetition covers the pair; a `.tdf` name never carries a wrap qualifier
//    twice, because the rewrap qualifier decrypt appends lands on a
//    `.decrypted.<ext>` name and so ends up in group 1.
// [non-capture group] - match how safari and chrome insert counters before extension.
//    I'm guessing this has some fascinating internationalizations but for now WFM is enough.
// 4: TDF container type extension
const QUALIFIER_TOKENS = [...ALGORITHM_SLUGS, 'kao=\\w+', 'kid=\\w+'];

export const ENCRYPTED_FILE_NAME = new RegExp(
  `^(.+)\\.([\\w-]+?)((?:-(?:${QUALIFIER_TOKENS.join('|')}))*)(?:-\\d+| \\(\\d+\\))?\\.(tdf|ztdf)$`
);

export type ParsedEncryptedFileName = {
  base: string;
  extension: string;
  /** Empty, or one or more `-token` segments *including* the leading `-`. */
  wrapQualifier: string;
};

export function parseEncryptedFileName(
  encryptedFileName: string
): ParsedEncryptedFileName | undefined {
  const m = encryptedFileName.match(ENCRYPTED_FILE_NAME);
  if (!m) {
    console.warn(`Unable to extract raw file name from ${encryptedFileName}`);
    return undefined;
  }
  return { base: m[1], extension: m[2], wrapQualifier: m[3] };
}

/**
 * Keeps the wrap qualifier the encrypt side added and records the mechanism the
 * client used for the rewrap exchange, so the two post-quantum legs are both
 * visible in the file name.
 */
export function decryptedFileName(
  encryptedFileName: string,
  rewrapAlgorithm: KasPublicKeyAlgorithm
): string {
  const rewrapQualifier = `-rwk-p=${algorithmSlug(rewrapAlgorithm)}`;
  const parts = parseEncryptedFileName(encryptedFileName);
  if (!parts) {
    return `${encryptedFileName}${rewrapQualifier}.decrypted`;
  }
  return `${parts.base}${parts.wrapQualifier}${rewrapQualifier}.decrypted.${parts.extension}`;
}

/**
 * The extension to offer the Save As picker. Falls back to `decrypted`, which
 * matches the suffix {@link decryptedFileName} produces on the same input.
 */
export function decryptedFileExtension(encryptedFileName: string): string {
  return parseEncryptedFileName(encryptedFileName)?.extension ?? 'decrypted';
}
