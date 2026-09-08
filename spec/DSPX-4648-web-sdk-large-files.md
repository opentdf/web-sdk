# DSPX-4648 — web-sdk: closing the gap to real 50TB TDF support

> Task `DSPX-4648`, under epic `DSPX-4502` (Large File TDF Security and Support). The workstream at
> the bottom is broken out as sub-tasks `DSPX-4650`…`DSPX-4654`, one per PR in the stack.
>
> | sub-task    | PR   | scope                                                                                                                                  |
> | ----------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------- |
> | `DSPX-4650` | PR 0 | pure sizing helpers + segment-integrity ADR ([`DSPX-4650-segment-integrity-algorithm.md`](./DSPX-4650-segment-integrity-algorithm.md)) |
> | `DSPX-4651` | PR A | manifest & segment-integrity scalability (item 1)                                                                                      |
> | `DSPX-4652` | PR B | derived encrypt byte ceiling (item 2)                                                                                                  |
> | `DSPX-4653` | PR C | full-buffer traps in `remote`/`stream` sources (item 3)                                                                                |
> | `DSPX-4654` | PR D | consumption-paced decrypt prefetch (item 4)                                                                                            |

## Context

PR #1018 (`DSPX-4496`) and PR #1017 (`DSPX-4591`) each fix a real correctness issue that matters at
very large scale: #1018 removes IV-collision risk in the BaseTDF cipher construction, and #1017
fixes the zip reader's EOCD/ZIP64 parsing so ZIP64 archives (which this SDK already writes
unconditionally) are read back correctly and robustly. A code audit was done to answer: given these
two PRs, what actually still stops web-sdk from creating and reading a genuine 50TB TDF today? The
audit found that the crypto and container format are sound at that scale, but several **policy
limits and buffering code paths** — untouched by either PR — are the real blockers. This document
tracks that follow-up work.

Cross-SDK zip64/threshold work (java-sdk `DSPX-4589`, go-sdk `DSPX-4590`) and the interop test
harness (`DSPX-4592`, in `opentdf/tests`) are already tracked and in flight elsewhere — this
document does not re-plan that work, only calls it out as an external dependency where relevant.

### Planning assumptions

- **50TB means 50 × 2^40 = 5.4976e13 bytes** throughout this document.
- **All sizing is computed for HS256 (HMAC-SHA256) segment integrity**, per team preference for HMAC
  over GMAC. This is the conservative case: an HS256 segment hash is 32 bytes (44 base64 chars)
  versus GMAC's 16 bytes (24 base64 chars), making each manifest segment entry ~56 bytes instead of
  ~36 — a 1.56x larger manifest. Sizing for HS256 means the numbers hold whether or not the default
  actually moves (see item 0).
- Per-segment manifest entry cost assumes PR #1017's optimization is in effect
  (`segmentSize`/`encryptedSegmentSize` omitted when they equal the default,
  `lib/tdf3/src/tdf.ts:705`), so an entry serializes as `{"hash":"…"},`.

## How PR #1018 and PR #1017 help

**PR #1018 (deterministic BaseTDF IVs)** — reserves AES-GCM IV 0 for encrypted metadata and assigns
sequential 96-bit big-endian IVs to payload segments starting at 1, with an explicit, enforced
ceiling (`MAX_GCM_INVOCATIONS_PER_KEY = 2**32`, `lib/tdf3/src/ciphers/gcm-iv-counter.ts`, throws
`ConfigurationError` in `GcmIvCounter.next()` rather than failing silently). This removes random-IV
collision risk that would otherwise grow with segment count, and turns an open-ended statistical
risk into a hard, tested, documented ceiling.

Concretely: the IV ceiling sets a **minimum** segment size of `5.4976e13 / 2^32 = 12,800 bytes`
(12.5 KiB) for a 50TB file. Every segment size this document considers is orders of magnitude above
that, so the IV ceiling is not the binding constraint — but it is the floor any future segment-size
change must stay above, and it must appear in the derived byte limit formula in item 2.

**PR #1017 (ZIP64/APPNOTE conformance)** — replaces the reader's brittle "scan the last 1000 bytes
for signature bytes" heuristic with real end-of-central-directory parsing, fixes the ZIP64
extra-field version-gate bug, fixes a duplicate-write bug in the non-ZIP64 data descriptor, and
fixes a cosmetic 32-bit-shift bug in an oversized-manifest error message. Critically, the audit
confirmed the underlying 64-bit field math (`readUInt64LE`/ `writeUInt64LE`,
`lib/tdf3/src/utils/zip-reader.ts`, `zip-writer.ts`) already uses multiplication/division rather
than bitwise ops and is guarded by `Number.isSafeInteger` — so ZIP64 offsets up to
`Number.MAX_SAFE_INTEGER` (~9e15, comfortably above 50TB's ~5.5e13) round-trip without precision
loss, and the writer already unconditionally emits ZIP64 structures. **The container format itself
has no inherent size ceiling; #1017 is what makes a correctly-produced large ZIP64 TDF reliably
parseable and hardens the reader against malformed archives.**

Together, these two PRs establish that the crypto scheme and container format are sound at 50TB
scale. They do not touch the policy limits or buffering code below.

## The sizing problem, stated once

Every item below is downstream of one table. Manifest segments-array size at 50TB, HS256 segment
integrity (~56 bytes/entry):

| Segment size | Segments   | Manifest | Notes                                 |
| ------------ | ---------- | -------- | ------------------------------------- |
| 1 MiB        | 52,428,800 | ~2.94 GB | today's default; 280x over 10MB cap   |
| 4 MiB        | 13,107,200 | ~734 MB  | still needs a large cap raise         |
| 16 MiB       | 3,276,800  | ~184 MB  | **recommended target**                |
| 64 MiB       | 819,200    | ~45.9 MB | coarse seek; large retry blast radius |
| ~280 MiB     | ~187,245   | ~10 MB   | only way to fit today's cap unchanged |

Two conclusions the previous revision of this document missed, and which drive the whole plan:

1. **Neither lever alone is sufficient.** Fitting 50TB under today's 10MB cap without raising it
   requires a ~280 MiB segment size — meaning ~280 MiB of plaintext plus ciphertext buffered per
   segment, and a single corrupt byte costing a 280 MiB re-fetch, because AES-GCM verification is
   all-or-nothing per segment. That is not viable in a browser. Conversely, keeping the 1 MiB
   default and only raising the cap requires a ~3 GB manifest, which forces the streaming-JSON and
   incremental-hash work to become hard blockers rather than optimizations. **The plan therefore
   moves both levers a moderate amount** rather than either one to an extreme.
2. **Recommended landing point: 16 MiB segments for large files + a 256 MiB manifest cap.** That
   yields a ~184 MB manifest (28% headroom under the cap), 3.28M segments (1,310x headroom under the
   2^32 IV ceiling), and a manifest that `JSON.parse` can still handle in one shot without a
   streaming parser (~3.3M objects, roughly 300–400 MB of transient V8 heap). This is the
   configuration the rest of the document is sized against.

## What's still blocking 50TB in web-sdk

### 0. Decide the segment integrity algorithm (blocks item 1's numbers) — **DONE** (`DSPX-4650`)

Today `lib/tdf3/src/client/index.ts:775-776` sets `integrityAlgorithm: 'HS256'` (root signature) but
`segmentIntegrityAlgorithm: 'GMAC'` (per-segment). Given the stated preference for HMAC, decide
explicitly whether per-segment integrity moves to HS256, because it changes every number in the
table above by 1.56x and carries a real throughput cost.

- [x] Decide: keep GMAC for segments, or move segments to HS256. **Decision: segments stay GMAC, the
      root signature stays HS256, and no default changes.** Recorded in
      [`DSPX-4650-segment-integrity-algorithm.md`](./DSPX-4650-segment-integrity-algorithm.md).
- [x] Record the throughput tradeoff in the decision. GMAC segment hashing is free — `getSignature`
      just returns the GCM auth tag already computed by the cipher (`content.slice(-16)`,
      `lib/tdf3/src/tdf.ts:371`). HS256 requires a **separate HMAC-SHA256 pass over every segment's
      ciphertext** (`lib/tdf3/src/tdf.ts:373`), i.e. an additional full 50TB of hashing on both
      encrypt and decrypt-verify. At 50TB that is not a rounding error.
- [x] Whatever is decided, size items 1 and 2 for HS256 (the conservative case) so the limits do not
      need re-derivation if the default changes later. `perSegmentEntryBytes(alg)` in
      `lib/tdf3/src/utils/scale-limits.ts` takes the algorithm as a parameter, so every derived
      limit is a function of it rather than of the shipped default; the landing point in item 1 is
      chosen to fit 50 TiB at 56 B/entry.

### 1. Manifest & segment-integrity scalability — the actual binding wall

`MANIFEST_MAX_SIZE = 10MB` (`lib/tdf3/src/utils/zip-reader.ts:18`) was historically enforced only at
decrypt time. Default segment size is 1MiB (`lib/tdf3/src/tdf.ts:83`,
`lib/tdf3/src/client/builders.ts:14`), producing the ~2.94 GB manifest in the table above.
Separately, the write and read paths both materialize several full per-segment arrays in memory
(detail below).

- [~] **Partially done:** validate manifest size at write/encrypt time too, so a TDF can never be
  written successfully and then be permanently unreadable. Implemented as
  `assertManifestWithinSizeLimit()` in `lib/tdf3/src/utils/zip-reader.ts:26`, called from
  `writeStream()` in `lib/tdf3/src/tdf.ts:609` before the manifest is emitted; throws a
  `ConfigurationError` naming the segment count and suggesting a larger `segmentSize`. Also fixed
  the `>> 10` bitwise-truncation bug in the read-side error message for manifests ≥ 4GiB. Covered by
  new tests in `lib/tests/mocha/unit/zip.spec.ts`.

  **This check is not fail-fast, and that gap is still open.** It runs at `tdf.ts:609`, _after_ the
  entire payload has been encrypted and enqueued to the controller. For a 50TB input that means
  burning the whole encrypt — days of work — before the error, and those bytes are already
  downstream, so a truncated archive is on the caller's disk or on the wire by the time it throws.
  The invariant ("never write something unreadable") holds; the useful half does not.

  - [ ] Add an **up-front** manifest-size estimate before the first segment is encrypted, for
        sources whose length is known (Blob `size`, `Content-Length`, chunker-reported size):
        `ceil(sourceSize / segmentSize) * perSegmentEntryBytes` versus the cap, where
        `perSegmentEntryBytes` is 56 for HS256 / 36 for GMAC. Keep the existing end-of-stream assert
        as a backstop for unknown-length sources.

- [ ] Raise `MANIFEST_MAX_SIZE` to 256 MiB and make it a configurable, documented value rather than
      a fixed constant. Read side and write side must share the value.
- [ ] Raise the default segment size for large inputs to 16 MiB (or auto-select by source size),
      keeping 1 MiB for small inputs so ordinary files are unaffected. Document the tradeoff: bigger
      segments = coarser seek granularity, larger decrypt-retry blast radius, and larger per-segment
      memory — which directly constrains item 4's prefetch window. Confirm this needs no
      manifest-schema coordination with go-sdk/java-sdk (PR #1017's notes suggest `segmentSize` is
      already optional there, which is promising).
- [ ] Replace the `Blob`-concatenation root-signature computation with incremental hashing (feed
      each segment hash into a running digest) on both write (`concatenateUint8Array` via
      `lib/tdf3/src/tdf.ts:539`) and read/verify (`:1435`); the helper itself is at `:1578`.

      **Sequencing note:** this is *not* urgent and should be done after the
      cap decision above, not before. While the 10MB cap stands, the concat
      buffer tops out around 100–150k segment hashes and is never large. Its
      real justification only appears once the cap is raised.

- [ ] Address the **other three** per-segment arrays, which incremental hashing does not touch. At
      3.28M segments (16 MiB) these are manageable; at 52.4M (1 MiB) each is independently
      multi-GB: - `segmentHashList` — one `Uint8Array` per segment, write and read - `segmentInfos`
      — the manifest `segments` array; must be fully materialized to be `JSON.stringify`'d -
      `chunks` — built eagerly via `segments.map(...)` at `lib/tdf3/src/tdf.ts:1482`, one object
      plus mailbox promise per segment. **This is why item 4 alone will not deliver bounded
      memory**: the scheduler paces _fetching_, not this allocation.
- [ ] Bound manifest `JSON.parse` on the read path (`lib/tdf3/src/utils/zip-reader.ts:132`). At the
      recommended 16 MiB / 256 MiB configuration a one-shot parse is acceptable and a streaming
      parser is **not** required — but the transient heap cost should be measured and documented,
      and the cap chosen so one-shot parsing stays viable. If a future cap raise pushes past ~512
      MB, revisit.

### 2. Hard 64GB `GLOBAL_BYTE_LIMIT`

`lib/tdf3/src/client/index.ts:67` (comment: "see WS-9363") silently clamps any caller-supplied
`byteLimit` above 64GB down to 64GB (`:719-722`).

Two scope corrections to the previous revision:

- The clamp exists **only in the tdf3 client path**. `writeStream` itself defaults `byteLimit` to
  `Number.MAX_SAFE_INTEGER` (`lib/tdf3/src/tdf.ts:417`), so callers driving the lower-level API
  directly are not subject to 64GB today. Both public entry points (`src/opentdf.ts:386` and the
  tdf3 client) do route through the clamp.
- The check is against `totalByteCount` — the **ZIP output size** — evaluated per output chunk in
  `_countChunk` (`lib/tdf3/src/tdf.ts:661`), so like item 1 it throws mid-stream after the bytes are
  already written. Same non-fail-fast shape, same fix shape.

- [ ] Investigate the original WS-9363 rationale before changing it.
- [ ] Replace the constant with a **derived** ceiling rather than a second arbitrary number:

      ```
      maxBytes = segmentSize * min(
        MAX_GCM_INVOCATIONS_PER_KEY,                      // IV ceiling, 2^32
        floor(manifestMaxSize / perSegmentEntryBytes)     // manifest ceiling
      )
      ```

      At the recommended configuration (16 MiB segments, 256 MiB cap, HS256 at
      56 B/entry) this yields a manifest ceiling of 4,793,490 segments and
      `maxBytes ≈ 80.4 TB` — comfortably above 50TB, with the IV ceiling
      (~72 PB at 16 MiB) not binding. At the current defaults it correctly
      collapses back to roughly today's behavior.

- [ ] Apply the same up-front check as item 1: when source length is known, compare against
      `maxBytes` before encrypting rather than after 64GB of output has been emitted.

### 3. Full-buffer traps in source handling

These are two different problems with opposite answers; the previous revision lumped them into one
checkbox.

**3a. Encrypt from a `'remote'` or `'buffer'` source — straightforward fix.** `sourceToStream`'s
`default:` branch (`lib/src/seekable.ts:196`) calls `chunker()` with no arguments, which for
`'remote'` issues an **unranged GET** that buffers the whole object. The `'chunker'` case
immediately above it (`:180`) already does the right thing with an 8 MiB ranged pull loop.

- [ ] Route `'remote'` through the same ranged-pull loop as `'chunker'`. Non-breaking; no API
      change.
- [ ] Leave `'buffer'` as-is — it is already fully in memory by construction, so there is nothing to
      stream. Document it as inherently size-limited.

**3b. Decrypt from a `'stream'` source — inherent, not a bug.** `lib/src/seekable.ts:162` and
`makeChunkable` in `lib/tdf3/src/client/index.ts:104` both drain the stream to a buffer (code
comment: _"we don't support streams anyways"_). This is not fixable in place: zip requires random
access because the EOCD is at the end of the archive, so a single-pass stream genuinely cannot be
decrypted without buffering or spooling to disk/OPFS.

- [ ] Decide between: (a) hard-reject `'stream'` decrypt with a `ConfigurationError` pointing at
      `'chunker'`/`'file-browser'`/ranged `'remote'`; or (b) buffer under a documented threshold and
      reject above it. **(b) is recommended** — (a) is a breaking change for existing callers
      passing small streams that work fine today, and would be a semver-major for a case the SDK
      currently supports.
- [ ] Whichever is chosen, call out the semver impact in the PR description.

The safe paths today remain `'chunker'`, `'file-browser'` (Blob), and the SDK's own ranged
`'remote'` reads used internally during segment decryption.

### 4. Default decrypt prefetch scheduler isn't consumption-paced

`updateChunkQueue` (`lib/tdf3/src/tdf.ts:1091`) prefetches in batches of 500 segments, up to 3
concurrent batches, without waiting for the consumer. The paced alternative
`createBoundedSegmentScheduler` (`:1207`) is opt-in only, selected at `:1509` when the caller sets
`segmentBatchSize`/`maxConcurrentSegmentBatches`.

- [ ] Make `createBoundedSegmentScheduler` the default, or auto-select it once file size/segment
      count crosses a threshold.
- [ ] **Budget the prefetch window in bytes, not segments.** This is a new constraint created by
      item 1: once segment size can be 16 MiB, a window expressed in segment counts is dangerous.
      The current opt-in defaults pattern of e.g. 8 segments × 3 batches is 24 MiB at 1 MiB segments
      but **384 MiB at 16 MiB segments** — untenable in a browser tab. Define the window as a byte
      budget (suggested: 64–128 MiB) and derive `segmentBatchSize` from `budget / segmentSize`.
- [ ] Choose and document concrete defaults for `segmentBatchSize` and
      `maxConcurrentSegmentBatches`; the plan previously named neither.
- [ ] **Call out the error-behavior change.** The legacy path swallows errors
      (`.catch(() => undefined)`, `lib/tdf3/src/tdf.ts:1118`) while the scheduler surfaces them via
      `onError`. Switching the default is arguably a bug fix, but it changes observable behavior and
      will break tests that depend on silent failure. Treat it as an intentional, documented change.
- [ ] Note that this item does **not** by itself bound decrypt memory — the eager `chunks`
      allocation in item 1 must also be addressed.

## Explicit non-goals

Called out so they are decisions rather than omissions:

- **Resumability and long-transfer credential lifetime.** A 50TB transfer at 1 Gbps is roughly five
  days. There is no checkpoint/resume story, and the KAS auth token will not survive the transfer.
  Genuine multi-day 50TB operation needs both; neither is in scope here, and "50TB supported" should
  be stated with that caveat until they are.
- **Compression.** Out of scope; the SDK stores payloads uncompressed.
- **Cross-SDK format negotiation** beyond confirming `segmentSize` optionality (tracked in
  `DSPX-4589`/`DSPX-4590`/`DSPX-4592`).

## TDD strategy: testing a size we can never allocate

50 TiB does not fit on a GitHub runner (public-repo `ubuntu-latest` is roughly 4 vCPU / 16 GB RAM /
~14 GB disk at time of writing — verify before relying on it), and it does not fit on a dev machine
either. Writing tests first is still possible, but only if the code is shaped so that the 50
TiB-specific behavior is reachable without 50 TiB of bytes. That shaping requirement is the most
important thing in this document, because it changes the implementation design.

### The core move: separate size arithmetic from byte movement

Nearly every blocker above is a **pure function of sizes**, not of data. Whether a manifest fits,
what the derived byte ceiling is, how many segments a source produces, how big a prefetch window may
be — none of that needs a single byte of payload to compute or to verify. Only the _streaming
mechanism_ needs real bytes, and the mechanism is size-invariant, so it can be verified at small
size.

So the first implementation step in every PR below is to extract the decision into a pure, exported,
separately-testable function. Proposed home: `lib/tdf3/src/utils/scale-limits.ts`.

```ts
perSegmentEntryBytes(alg: IntegrityAlgorithm): number;
estimateManifestBytes(opts: {
  sourceSize: number;
  segmentSize: number;
  alg: IntegrityAlgorithm;
  assertionBytes?: number;
}): number;
maxEncryptableBytes(opts: {
  segmentSize: number;
  manifestMaxSize: number;
  alg: IntegrityAlgorithm;
}): number;
chooseSegmentSize(opts: { sourceSize: number; manifestMaxSize: number; alg }): number;
deriveSegmentBatchSize(opts: { segmentSize: number; byteBudget: number }): {
  segmentBatchSize: number;
  maxConcurrentSegmentBatches: number;
};
```

Every one of these can be red/green tested at a literal `50 * 2 ** 40` in microseconds with zero
allocation. This is TDD driving design, not testing bolted on afterward: if these stay inline inside
`writeStream`, the 50 TiB behavior is only reachable by actually encrypting 50 TiB, and the plan
becomes untestable.

### The extrapolation argument

Since we can never run the real thing, the test suite has to _argue_ that 50 TiB works rather than
demonstrate it. The argument has three links, and each link is independently testable at feasible
cost:

1. **The arithmetic is right at 50 TiB.** Pure-function tests, exact expected values, no data.
   (Covers: will it be rejected? what limit is derived? what segment size is chosen?)
2. **The arithmetic faithfully predicts the real writer.** A property test: for many
   `(sourceSize, segmentSize, alg, assertions)` combinations at _small_ sizes,
   `estimateManifestBytes(...)` must be **≥** the byte length of the manifest `writeStream` actually
   emits — never an under-estimate. Verified at KB-to-MB scale where both sides are cheap to
   compute.
3. **The mechanism is size-invariant.** A scale-invariance sweep showing peak live memory is flat
   across a 4x–8x range of feasible sizes, so it stays flat at 50 TiB.

Link 2 is the one that carries the extrapolation. If the estimator is provably conservative at small
scale and the arithmetic is exact at large scale, then the 50 TiB claim follows without ever running
it. **Write link 2 first** — it is the test most likely to find a real bug, because the naive
estimator is wrong in at least three ways: the final partial segment carries explicit `segmentSize`
and `encryptedSegmentSize` fields (so its entry is ~96 bytes, not ~56), base64 padding varies, and
caller-supplied assertions are unbounded and only sized after signing. That last one means the
up-front check can never be exact, which is precisely why the end-of-stream assert in item 1 must
stay as a backstop.

### Techniques, and what each one buys

| Technique                     | Reaches            | Cost        | Covers                                                 |
| ----------------------------- | ------------------ | ----------- | ------------------------------------------------------ |
| Pure sizing functions         | true 50 TiB        | ~0          | items 0, 1 (estimator), 2, 4 (window)                  |
| Tiny segments, real bytes     | 10^5–10^6 segments | ~10s of MB  | array materialization, IV sequencing, scheduler pacing |
| Synthetic `segmentInfos`      | 3.3M entries       | ~1 GB heap  | manifest stringify/parse viability, cap enforcement    |
| Virtual chunker + stub crypto | huge logical size  | O(segments) | end-to-end shape, up-front rejection                   |
| Scale-invariance sweep        | 64–512 MiB         | ~1 min      | streaming guarantee, bounded memory                    |

Two of these deserve elaboration.

**Tiny segments decouple segment count from byte count.** Every array and scheduler path in item 1
and item 4 scales with the _number of segments_, not the number of bytes. A 100 MB payload at a
64-byte segment size produces ~1.6M segments — the same code path pressure as a multi-TB file at
realistic segment sizes, for 100 MB of data and a few seconds. This is the cheapest way to get
genuine high-segment-count coverage, and it should be the workhorse for items 1 and 4. Caveat: it
runs below the segment-size validation layer, so those tests must construct config directly rather
than going through the public builders, and they must not be used to validate anything IV-related
that depends on the 12.5 KiB floor.

**Stub the `CryptoService` to make segments O(1).** `CryptoService` is already a plain injectable
object (`cfg.cryptoService`, DI precedent in `tests/mocha/unit/crypto-di.spec.ts`), so a
counting/identity implementation of `encrypt`/`decrypt`/`hmac` turns per-segment cost from "hash and
encrypt N bytes" into a function call plus a counter bump. Combined with a virtual chunker this
makes a multi-million-segment logical run tractable. It deliberately does **not** test the crypto —
real crypto is covered by the existing suites at normal sizes — it tests the plumbing around it.

### What we will never test, and why that is acceptable

- **A real 50 TiB round trip.** Not in CI, not on a dev box. The one-off manual validation below
  against a sparse file is the closest we get, and the support statement is qualified accordingly.
- **The rejected 1 MiB / 52.4M-segment configuration, materialized.** Building that manifest needs
  ~10 GB of heap. It is tested by _arithmetic and rejection_ only: assert `estimateManifestBytes`
  rejects it, and assert the rejection is O(1) — that the chunker was never called and no segment
  array was allocated. That assertion is itself the feature (item 1's fail-fast gap), so the cheap
  test and the desired behavior coincide.
- **Wall-clock throughput.** Deferred entirely to the manual run.

## Recommended web-sdk workstream (sequenced)

Each PR below is written red-first: the listed tests are expected to fail (or fail to compile, where
the module does not exist yet) before any implementation lands.

**PR 0 — Segment integrity algorithm decision.** Item 0. Small, but it fixes the constants every
later PR is sized against.

- 🔴 `perSegmentEntryBytes('HS256') === 56` and `perSegmentEntryBytes('GMAC') === 36`, plus a test
  asserting these match a real single-segment manifest entry byte-for-byte (guards against the
  constant silently drifting from the serializer).
- 🟢 Land the constant, the ADR, and the default flip if the decision goes that way.

**PR A — Manifest & segment-integrity scalability (do first after PR 0).** Item 1. Everything else
is sized relative to this. Land the cap raise and the segment-size change together — neither is
useful alone.

- 🔴 **Conservativeness property** (link 2 of the extrapolation argument, write this first): across
  a seeded sweep of small `(sourceSize, segmentSize, alg, assertion count)` combinations,
  `estimateManifestBytes(...) >=` the actual emitted manifest length. Expect this to fail initially
  on the final partial segment.
- 🔴 **Exact arithmetic at 50 TiB**: the table in "The sizing problem" becomes a table-driven test —
  `(1 MiB → ~2.94 GB, 16 MiB → ~184 MB, 64 MiB → ~45.9 MB)` at HS256, and the GMAC column too.
- 🔴 **O(1) rejection**: encrypting a virtual 50 TiB source at 1 MiB segments throws
  `ConfigurationError` _before_ the chunker is called once and before any segment array is
  allocated. Assert on the chunker call count, not on timing.
- 🔴 **Backstop still fires**: an unknown-length source that overruns the cap mid-stream still
  throws at `writeStream`'s end-of-stream assert.
- 🔴 **High segment count**: tiny-segment run at ~10^6 segments round-trips correctly, with root
  signature and IV sequence intact.
- 🔴 **Manifest at recommended scale**: synthetic 3.28M-entry `segmentInfos` stringifies and
  re-parses within the 256 MiB cap and a documented heap budget.
- 🟢 Implement `scale-limits.ts`, the up-front check, the cap raise, the segment-size selection,
  incremental root hashing, and the per-segment array work.

**PR B — Derive `GLOBAL_BYTE_LIMIT` from PR A's numbers.** Item 2. Depends on PR A having fixed
`manifestMaxSize` and the default segment size.

- 🔴 `maxEncryptableBytes({segmentSize: 16 MiB, manifestMaxSize: 256 MiB, alg: 'HS256'}) ≈ 80.4 TB`,
  and `> 50 TiB`; at today's defaults it collapses to roughly today's behavior.
- 🔴 The IV ceiling binds instead of the manifest ceiling for very large segment sizes — a test that
  exercises the _other_ branch of the `min()`.
- 🔴 The 12.5 KiB minimum segment size for 50 TiB is asserted somewhere, so a future segment-size
  change cannot silently cross the IV floor.
- 🔴 Over-limit sources are rejected up front, matching PR A's O(1) rejection test, rather than
  after 64GB of output.
- 🟢 Replace the constant with the derived formula.

**PR C — Remove or guard full-buffer traps in stream/remote sources.** Item 3. Independent of A and
B; can land in parallel.

- 🔴 (3a) A mock ranged HTTP source used for _encrypt_ receives multiple `Range` requests and never
  an unranged GET; assert on recorded request headers, and assert peak buffered bytes stay near the
  pull size rather than the object size.
- 🔴 (3b) A `'stream'` decrypt source above the threshold throws `ConfigurationError` naming
  `'chunker'`/`'file-browser'`/ranged `'remote'`; below the threshold it still works, pinning the
  non-breaking half.
- 🟢 Route `'remote'` through the ranged loop; add the threshold policy.

**PR D — Default to consumption-paced decrypt prefetch.** Item 4. Must land after PR A, because the
byte-budgeted window depends on the new segment size.

- 🔴 **Byte-budget invariance** (the specific regression this guards): `deriveSegmentBatchSize`
  yields the same byte budget at 1 MiB and at 16 MiB segments — i.e. the window shrinks in segment
  count as segment size grows, and never returns the 384 MiB window the current segment-count
  defaults would produce.
- 🔴 **Pacing**: with a manually-pumped consumer that reads N segments then stops, in-flight fetches
  stay within the window and do not run ahead to completion. Deterministic — no timers, no
  wall-clock.
- 🔴 **Errors surface**: a failing segment fetch rejects the output stream rather than being
  swallowed the way `.catch(() => undefined)` does today. This test encodes the intentional behavior
  change.
- 🔴 **`chunks` allocation is not eager**: for a high-segment-count decrypt, live per-segment
  objects stay bounded rather than scaling with total segments. Expect this to fail until item 1's
  eager `segments.map(...)` is addressed — it is the test that proves PR D alone is insufficient.
- 🟢 Make the bounded scheduler the default with byte-budgeted parameters.

## Test tiers and CI wiring

True end-to-end 50TB testing isn't practical in CI (storage + time), so the suite is split into
tiers with different budgets. Only the first tier runs on every PR.

| Tier                   | Runs                   | Budget                                | Contents                                                                                                |
| ---------------------- | ---------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `test:mocha` (default) | every PR               | seconds                               | pure sizing functions, conservativeness property, O(1) rejection, byte-budget derivation, ZIP64 offsets |
| `test:scale` (new)     | every PR, separate job | ~2–5 min, `--max-old-space-size=8192` | high-segment-count runs, synthetic 3.3M-entry manifest, scale-invariance sweep                          |
| manual                 | once, pre-release      | out of band                           | sparse-file CLI run, throughput                                                                         |

Notes on wiring:

- Add a `test:scale` script alongside the existing `test:mocha` (`package.json` runs mocha over
  `dist/web/tests/mocha/**/*.spec.js` under `c8`). Keep it a **separate job**, not a separate opt-in
  flag — a tier that only runs when someone remembers to run it will rot.
- Exclude the scale tier from the coverage thresholds in `coverage:merge`; its job is resource
  behavior, not line coverage, and mixing it in will make the thresholds noisy.
- The scale tier is Node-only. Do not add it to `test:wtr` or `test:browser` — the heap headroom
  isn't there, and the behavior under test is not browser-specific.
- Give scale tests explicit timeouts rather than inheriting mocha's default, and name them with the
  configuration under test (e.g. `50TiB@16MiB/HS256`) so a failure says which point in the table
  broke.

### Test inventory

- **Synthetic chunker/source test double**: a `Chunker`/`Source` implementation that reports a huge
  logical size and generates deterministic bytes on demand (e.g. PRNG seeded by offset) without
  materializing the full file.

  **Caveat that limits this technique:** the synthetic chunker makes a large _logical_ size cheap,
  but the per-segment crypto cost is real. A "50TB" run at 1 MiB segments is still 52.4M AES-GCM
  operations plus, under HS256, 52.4M HMAC passes — not CI-feasible at any segment size that also
  exercises the default configuration. Use it for the _shape_ of the code path (bounded memory,
  correct segment indexing, IV sequencing) at a few hundred thousand segments, and rely on the unit
  tests below for true 50TB-scale numbers. Be explicit in the test name about which configuration is
  being exercised.

- **Manifest-scale unit tests**: directly unit-test manifest construction/ parsing, the up-front
  size estimate, and root-signature computation against a synthetic list of millions of segment-hash
  entries (not full segments). This is where the real 50TB-scale validation lives, because it skips
  the crypto. Cover both 56 B/entry (HS256) and 36 B/entry (GMAC) sizing.
- **Byte-budget prefetch tests**: assert that the window derived for 16 MiB segments holds the same
  _byte_ budget as for 1 MiB segments — the specific regression item 4 is guarding against.
- **GCM-IV ceiling tests**: already covered inline in `lib/tests/mocha/unit/tdf.spec.ts`
  (`describe('GcmIvCounter', ...)`) — boundary at the invocation ceiling, metadata-IV-0 reservation,
  multi-byte carry. No further work needed here unless the ceiling itself changes. Add one case
  asserting the 12.5 KiB minimum-segment-size floor is documented wherever the derived byte limit of
  item 2 is computed.
- **ZIP64 boundary/offset tests**: extend `lib/tests/mocha/unit/zip.spec.ts` with round-trips at
  true 50TB-scale offsets (~5.5e13; a `2**50` case already exists) plus a case just under/over
  `Number.MAX_SAFE_INTEGER` to confirm the existing guard rejects it correctly.
- **Memory-ceiling regression test**: encrypt/decrypt a moderately large synthetic file while
  asserting memory stays roughly constant. **Do not assert on RSS or `process.memoryUsage()`** — GC
  nondeterminism makes that flaky in both Node and browsers, and it will be quarantined within a
  month. Instead instrument the chunker to count concurrently-live segment buffers, or count
  allocations through a test-only hook, and assert on that.
- **Manual/perf validation**: once PRs 0–D land, do a one-off manual run using the CLI
  (`cli/src/cli.ts`, already confirmed to stream via `openAsBlob`/ `createWriteStream`/`pipeTo`)
  against a large sparse file or cloud object store, out-of-band, to sanity-check real
  throughput/timing before calling 50TB "supported." Do not attempt to allocate or transfer real
  50TB in automated tests — use sparse files or the synthetic chunker instead. Include the
  HS256-versus-GMAC throughput delta from item 0 in this measurement.

## Verification

- `cd lib && npm test` and `npm run lint` after each PR, plus the new `npm run test:scale` tier.
- Each PR's 🔴 tests were demonstrated failing before its implementation landed — for the sizing
  work this matters more than usual, since a test that passes against a not-yet-written estimator is
  a test that isn't measuring anything.
- The conservativeness property (link 2) passes across the full seeded sweep, since the 50 TiB claim
  rests on it rather than on any executed run.
- Manual CLI dry run against a sparse multi-GB file to confirm real streaming behavior end-to-end
  before declaring the workstream complete.
- Statement of support is qualified by the non-goals above — specifically, no resume and no
  multi-day credential story.
