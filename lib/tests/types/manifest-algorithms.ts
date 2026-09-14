/**
 * Type-level assertions about the manifest's algorithm fields.
 *
 * `tdf3/src/tdf.ts` documents the invariant it relies on:
 *
 *   > The type carries the invariant so a root algorithm cannot even be
 *   > *typed* as `'GMAC'`.
 *
 * `RootIntegrityAlgorithm` does carry it. The manifest field does not:
 * `alg: RootIntegrityAlgorithm | string` is absorbed by TypeScript into plain
 * `string`, so the named member is inert and `alg = 'GMAC'` — the one value an
 * attacker controls — compiles clean. Same for
 * `segmentHashAlg?: SegmentIntegrityAlgorithm | string`. Before DSPX-4703 the
 * field was `SegmentIntegrityAlgorithm`, which was the only compile-time
 * constraint on `writeStream` and `SplitKey.write`; the sole remaining guard is
 * an unchecked `as RootIntegrityAlgorithm` cast.
 *
 * Each `@ts-expect-error` below is the assertion: if the assignment is legal,
 * the directive is unused and `tsc` reports TS2578. Resolving this means either
 * restoring a type that narrows (e.g. a separate raw/wire manifest shape that
 * `asRootIntegrityAlgorithm` narrows into the strict one) or writing the field
 * as plain `string` and correcting the comment in `tdf.ts` — but not both
 * claims at once, which is the state today.
 *
 * Checked by `npm run test:types`; excluded from the build so that a failure
 * here does not hide the runtime specs.
 */
import { type EncryptionInformation } from '../../tdf3/src/models/encryption-information.js';
import { type RootIntegrityAlgorithm, type SegmentIntegrityAlgorithm } from '../../tdf3/src/tdf.js';

declare const info: EncryptionInformation['integrityInformation'];

// The narrow types themselves are fine; these are the controls.
const root: RootIntegrityAlgorithm = 'HS256';
const segment: SegmentIntegrityAlgorithm = 'GMAC';
// @ts-expect-error -- 'GMAC' is not a root integrity algorithm
const badRoot: RootIntegrityAlgorithm = 'GMAC';
// @ts-expect-error -- 'CRC32' is not a segment integrity algorithm
const badSegment: SegmentIntegrityAlgorithm = 'CRC32';

// The manifest fields must carry the same invariant.
info.rootSignature.alg = root;
// @ts-expect-error -- a root algorithm must not be typable as GMAC
info.rootSignature.alg = 'GMAC';
// @ts-expect-error -- nor as an arbitrary string
info.rootSignature.alg = 'HS2566';

info.segmentHashAlg = segment;
// @ts-expect-error -- nor may a segment algorithm be an arbitrary string
info.segmentHashAlg = 'CRC32';

export { badRoot, badSegment };
