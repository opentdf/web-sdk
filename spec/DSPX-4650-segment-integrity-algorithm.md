# DSPX-4650 — ADR: segment integrity algorithm for large TDFs

> Status: **accepted**, 2026-09-08. Context: item 0 of
> [`spec/DSPX-4648-web-sdk-large-files.md`](./DSPX-4648-web-sdk-large-files.md), which blocks the
> sizing in item 1.

## Decision

Per-segment integrity stays **GMAC**. The root payload signature stays **HS256**. Neither default
changes in this PR.

Every size limit in the large-file work is nonetheless **derived for HS256**, the more expensive of
the two, so that moving the default later needs no re-derivation and loosens no limit.

## Why this had to be decided first

The manifest carries one `segments[]` entry per segment, and the digest inside that entry is the
only part of the manifest that scales with payload size. Its length is a direct function of the
algorithm:

| alg   | digest | base64 | entry (`{"hash":"…"},`) |
| ----- | ------ | ------ | ----------------------- |
| GMAC  | 16 B   | 24 B   | **36 B**                |
| HS256 | 32 B   | 44 B   | **56 B**                |

`perSegmentEntryBytes()` in `lib/tdf3/src/utils/scale-limits.ts` is that table, and it is the
constant every number in the plan is multiplied out of. At 50 TiB with 16 MiB segments the
difference is 118 MB of manifest versus 184 MB — a 1.56× factor on the single quantity the whole
plan is trying to bound. Choosing a segment size, a manifest cap, or a maximum encryptable payload
without first fixing this constant would just mean redoing all three.

## The tradeoff

**GMAC is free.** `getSignature()` (`lib/tdf3/src/tdf.ts:369-372`) returns `content.slice(-16)` —
the AES-GCM authentication tag the cipher already computed while encrypting the segment. No
additional pass over the data, no additional key use, nothing to schedule.

**HS256 is a second full pass.** `getSignature()` falls through to
`cryptoService.hmac(content, unwrappedKey)`, an HMAC-SHA256 over the entire segment ciphertext. At
50 TiB that is 50 TiB of extra hashing on encrypt, and another 50 TiB on decrypt for anyone who
verifies. In a browser this competes with the encrypt itself for the same main thread or the same
WebCrypto queue.

Set against that, HS256 gives an integrity value that is independent of the cipher. GMAC's tag is a
property of the AES-GCM construction: it authenticates the ciphertext under the same key that
encrypted it. That is real integrity — it is the tag GCM decryption already checks — but it is not a
separate statement, and it inherits every property of the GCM key. HS256 keys the HMAC from the same
unwrapped key today (`getSignature` takes `unwrappedKey`), so the independence is weaker in practice
than it looks in principle.

For the segment level, where the value is recomputed on every read and multiplied by up to millions
of entries, the cost is not worth that difference. For the root signature, which is computed once
over the concatenated segment hashes rather than over the payload, the cost is negligible and HS256
stays.

That split — HS256 root, GMAC segments — is what `lib/tdf3/src/client/index.ts:775-776` already
sets, unconditionally, for both the `tdf3` client and the `opentdf.ts` entrypoint. There is no
public knob to change it. The decision here is to leave that as it is, and to write down why, rather
than to discover the reasoning again the next time the manifest gets too big.

## Why the limits are sized for HS256 anyway

Sizing against the default we ship would couple every limit to a value we might want to change. Two
things could move it: a customer or profile that requires an integrity value not derived from the
encryption key, or a future cipher-agnostic segment format. Either would raise
`perSegmentEntryBytes` by 1.56×, and if the limits had been derived at 36 B they would all silently
under-count.

So `estimateManifestBytes()` and everything built on it take `alg` as an input, and the plan's
landing point (16 MiB segments, 256 MiB manifest cap) is chosen so that 50 TiB fits **at 56
B/entry**. Running at 36 B/entry simply leaves headroom. The limits are correct for whichever
default is in force, and moving the default is a one-line change rather than a re-derivation.

## Consequences

- No behavioural change ships in this PR. `perSegmentEntryBytes` is a new pure function; nothing
  calls it yet.
- The constants are pinned by tests that measure a real emitted manifest rather than a hand-built
  one: `lib/tests/mocha/unit/scale-limits.spec.ts` writes a 4-segment and a 5-segment TDF and
  asserts the delta equals `perSegmentEntryBytes(alg)` exactly, for both algorithms. If the
  serializer ever changes shape — a renamed field, a new per-segment key — that test fails rather
  than the estimate silently drifting.
- If the segment default does move to HS256, the manifest for a given payload grows 1.56× and
  encrypt does a second pass over the payload. Nothing in the large-file work needs to change to
  accommodate it.
