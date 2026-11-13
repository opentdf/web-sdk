---
ticket: DSPX-5162
title: "web-sdk CLI: evaluate Bun and Deno as alternatives to Node for large-file support"
status: draft
authors: [dmihalcik@virtru.com]
branches: [opentdf/web-sdk:DSPX-5162-evaluate-bun-and-deno-vs-node-for-web-sdk-cli, opentdf/tests:DSPX-5162-evaluate-bun-and-deno-vs-node-for-web-sdk-cli]
prs: []
created: 2026-10-15
updated: 2026-10-15
---

# web-sdk CLI: Bun and Deno vs Node for large files

## Summary

`@opentdf/ctl` opens its input with `node:fs` `openAsBlob`, and on Node that
Blob's size is wrong mod 2^32 (DSPX-5160, nodejs/node#66207). As a result
the CLI cannot decrypt a TDF of 4 GiB or more. This doc checks whether Bun
or Deno avoids the problem and whether either could run the CLI.

**Recommendation: stay on Node, with the DSPX-5160 positional chunker and
bounded segment prefetch in the CLI. Treat Bun as a best-effort
alternative, not a supported one. Do not offer Deno.**

- **Bun** gets file Blob sizes and offsets past 2^32 right. It is as fast as
  Node at 59 GiB (about 10% less wall time, about half the CPU). But the
  released CLI fails *every* decrypt under Bun, at any size, because of a
  Bun `Blob.slice(-n)` bug. This branch includes a one-line SDK fix for it.
  Bun also ignores stdout backpressure: piping a 59 GiB decrypt went past
  4 GiB RSS within about a second.
- **Deno** has no file-backed Blob, and its `openAsBlob` shim reads the whole
  file into memory. Its WebCrypto AES-GCM runs at about 186 MiB/s per stream,
  roughly 25x slower than Node or Bun. With the DSPX-5160 chunker it does
  complete a 59 GiB decrypt, but takes 118 s where Node and Bun take 8–10 s.
- **No runtime fixes large files alone.** The CLI never sets
  `segmentBatchSize` / `maxConcurrentSegmentBatches`, so decrypt prefetches
  segments without bound. Once a runtime can read past 4 GiB, RSS grows
  towards the file size: Node, Bun and Deno all passed a 4 GiB cap within
  1–2 s. That needs a CLI change (proposed follow-up) whatever the runtime.

## Environment and method

- Apple M5 Pro, 48 GiB RAM, macOS (Darwin 27), APFS SSD.
- Node **24.21.0** (nvm), Bun **1.4.3** (Homebrew; npm `bun@1.4.3` identical),
  Deno **2.9.6** (npm `deno@2.9.6`, into a scratch prefix).
- CLI: `@opentdf/ctl@0.20.0`, the latest on npm, as installed by
  `otdf-sdk-mgr` into `xtest/sdk/js/dist/v0.20.0`.
- Inputs:
  - a sparse 5 GiB file (5,368,709,127 bytes) with `MIDMARK!` at 2^32+100
    and `TAILBYTES-0123AB` as its last 16 bytes;
  - the read-only 64 GiB go TDF from the `--bench-scale` run
    (68,723,312,361 bytes; EOCD in the last 22 bytes; central directory 270
    bytes from the end);
  - a 59 GiB TDF (63,354,636,051 bytes; plaintext is a 59 GiB sparse file
    ending `TAILBYTES-59GiB!`) that Bun encrypted against a mock KAS.
- **The local platform at :8080 was down for the whole session** (Keycloak at
  :8888 was up), so no decrypt went through a real KAS. CLI round trips used a
  ~90-line Connect-JSON mock KAS: a throwaway RSA key, `PublicKey` and
  `Rewrap` only, and no policy or auth checks. Because of this, the 64 GiB
  go/java TDFs could only be measured with an offline proxy (read every
  segment + WebCrypto AES-256-GCM), not decrypted.
- Every multi-GiB process ran under a watchdog that killed the process
  group above 4 GiB RSS. "Capped" below means the process was killed there.

## 1. File Blob correctness above 4 GiB

| Probe | Node 24.21.0 | Bun 1.4.3 | Deno 2.9.6 |
|---|---|---|---|
| `openAsBlob` size, 5 GiB sparse | **1,073,741,831** (mod 2^32) | 5,368,709,127 ✔ | 5,368,709,127 ✔ |
| `openAsBlob` size, 64 GiB TDF | **3,835,625** (mod 2^32) | 68,723,312,361 ✔ | process killed: the shim read the file into memory |
| `openAsBlob().slice(2^32+100, +8)` | **empty** | `MIDMARK!` ✔ | `MIDMARK!` ✔ |
| `openAsBlob().slice(n-270, n-266)` on TDF | **empty** | `504b0102` (CD sig) ✔ | n/a (killed) |
| `openAsBlob().slice(-16)` / `slice(-22)` | **wrong bytes** (offset taken from the truncated size) | **empty** unless `.size` was read first ✘ | ✔ |
| Native file Blob | none (`openAsBlob` *is* it) | `Bun.file()`: size and `slice(a,b)` ✔; `slice(-n)` has the same empty-until-`.size` bug | **none**; `Deno.open` + `seek(-270, End)` + `read` ✔ |
| `openAsBlob` memory | lazy | lazy | **eager**: RSS about 2x file size (300 MiB → 663 MB; 5 GiB → 10.8 GB) |
| `node:fs` `FileHandle.read(buf, …, position > 2^32)` | ✔ | ✔ | ✔ |

Bun bug, minimal repro (any file size):

```js
await Bun.file(p).slice(-4).arrayBuffer();               // 0 bytes (slice(-4).size reports 4)
const b = Bun.file(p); b.size; await b.slice(-4).arrayBuffer(); // 4 bytes
```

The SDK's zip reader opens every TDF with `getChunk(-1000)`. Under Bun that
returns nothing, and decrypt fails with `Unable to retrieve CD manifest`.

## 2. Running the CLI unmodified

Tiny encrypt then decrypt against the mock KAS. Encrypt includes
`--containerType tdf3`; decrypt includes `--ignoreAllowList`.

| | Node | Bun | Deno |
|---|---|---|---|
| `--version`, `help` | ✔ | ✔ | ✔ (help says `Usage: deno`: yargs `$0`) |
| encrypt | ✔ | ✔ (Node decrypts its output byte-for-byte) | ✔ |
| decrypt | ✔ | **✘ every TDF**: `Unable to retrieve CD manifest` (`slice(-n)` bug). ✔ with the SDK fix in this branch | ✔ |
| npm-style launch | `npx @opentdf/ctl` | `bunx --bun @opentdf/ctl`. Plain `bunx` follows the `#!/usr/bin/env node` shebang and silently runs **Node** | `deno run -A npm:@opentdf/ctl@0.20.0` ✔ |
| single binary | (Node SEA: not tested) | `bun build --compile`: 0.1 s build, 72 MB, round trip ✔ (with SDK fix) | `deno compile -A`: 3.8 s build, 76 MB, round trip ✔ |
| Decrypt to stdout, 59 GiB, piped | ✔ (backpressure honoured) | **✘ RSS > 4 GiB in about 1 s**: `Writable.toWeb(process.stdout)` ignores backpressure. `--output <file>` is fine (570 MB RSS) | not tested at 59 GiB (too slow to outrun a pipe); 5 GiB ✔ |

These worked under all three runtimes, as far as a tiny round trip exercises
them:

- yargs parsing;
- Keycloak client-credentials fetch;
- the connect-rpc client (`@connectrpc/connect-web` over `fetch`, HTTP/1.1);
- WebCrypto: RSA-OAEP wrap/unwrap, RS256 request signing, AES-256-GCM,
  HMAC/GMAC integrity;
- Web Streams `pipeTo(Writable.toWeb(createWriteStream()))`;
- `node:fs`, `node:stream` and `node:fs/promises`.

Not exercised: EC wrapping (`ec:secp256r1`), ML-KEM, assertions, DPoP
nonce challenges, and HTTP/2. The mock KAS only does RSA, and connect-web
never uses HTTP/2.

Deno note: it needs `-A` (or at least `--allow-read --allow-write
--allow-net --allow-env`).

## 3. Large-file behaviour

### 3a. CLI decrypt of the 59 GiB TDF to `/dev/null` (mock KAS)

The scratch copy of the CLI had env-gated patches:

- **fh chunker**: a `FileHandle.read`-by-position `Chunker`, standing in for
  DSPX-5160;
- **blob**: `openAsBlob` plus this branch's negative-offset fix;
- **bounded**: `segmentBatchSize=16`, `maxConcurrentSegmentBatches=3`.

Wall time includes the token fetch and rewrap (about 0.3 s). Three runs each
for Node and Bun; the ranges are min–max.

| Runtime / source | Wall (s) | Throughput | CPU user+sys (s) | Peak RSS | Result |
|---|---|---|---|---|---|
| Node, unmodified 0.20.0 | 0.3 | n/a | n/a | 114 MB | ✘ `Unable to retrieve CD manifest` (size mod 2^32) |
| Bun, unmodified 0.20.0 | 0.2 | n/a | n/a | 81 MB | ✘ `Unable to retrieve CD manifest` (`slice(-n)`) |
| Deno, unmodified 0.20.0 | n/a | n/a | n/a | > 4 GiB at about 1 s | ✘ capped (eager `openAsBlob`) |
| Node, fh chunker, **unbounded** | n/a | n/a | n/a | > 4 GiB at about 1 s | ✘ capped (unbounded prefetch) |
| Bun, blob, **unbounded** | n/a | n/a | n/a | > 4 GiB at about 1 s | ✘ capped (unbounded prefetch) |
| **Node, fh chunker, bounded** | 9.1–9.9 | **6.0–6.5 GiB/s** | 38.6–40.3 + 8.5–9.3 | 0.93–0.96 GB | ✔ (stdout run: 63,350,767,616 bytes, tail ✔) |
| **Bun, blob, bounded** | 8.1–8.3 | **7.1–7.3 GiB/s** | 14.5–14.6 + 9.5–9.6 | 1.46–1.59 GB | ✔ (FIFO run: 63,350,767,616 bytes, tail ✔) |
| Bun, fh chunker, bounded | 7.9–8.2 | 7.2–7.5 GiB/s | 14.3–14.4 + 9.4–9.8 | 1.59–1.76 GB | ✔ |
| Deno, fh chunker, bounded | 118 | 0.50 GiB/s | 375 + 9 | 0.54 GB | ✔ |

A 5 GiB decrypt under Bun (blob, bounded) also produced output whose SHA-256
matched the plaintext.

### 3b. Offline proxy on the 64 GiB go TDF

No KAS was available. The proxy reads all 32,769 segments of 2,097,180 bytes
and AES-256-GCM-encrypts each one with WebCrypto, 4 in flight. Encryption
costs the same as decryption here.

| Runtime / reader | Wall (s) | MiB/s | CPU user+sys (s) | Peak RSS |
|---|---|---|---|---|
| Node, `FileHandle.read` | 7.1 | 9,184 | 18.1 + 5.9 | 251 MB |
| Bun, `openAsBlob().slice()` | 9.0 | 7,256 | 12.5 + 9.6 | 114 MB |
| Bun, `FileHandle.read` | 8.1 | 8,046 | 12.9 + 8.1 | 157 MB |
| Deno, `FileHandle.read` | 98.1 | 669 | 371.8 + 9.3 | 149 MB |
| Node, `openAsBlob().slice()` | n/a | n/a | n/a | n/a: ✘ short read at segment 512 (offset 1 GiB = 5 GiB mod 4 GiB, sparse run) |

WebCrypto AES-256-GCM on one stream (2 MiB chunks, depth 1, 5 GiB): Node
4,766 MiB/s, Bun 4,584 MiB/s, **Deno 186 MiB/s**. The java 64 GiB TDF has the
same 2 MiB segment layout and was not measured separately.

### 3c. Encrypt (not the subject, recorded for completeness)

The CLI's encrypt reads with `Blob.stream()`, which is not truncated on Node.
A 5 GiB encrypt produced a correct 5,369,038,724-byte TDF.

| | 5 GiB | 59 GiB |
|---|---|---|
| Node | 136 s, 0.80 GB RSS | not run |
| Bun | 84 s, 0.47 GB RSS | 1,001 s (60 MiB/s), 1.77 GB RSS |
| Deno | ✘ capped at about 1 s (eager `openAsBlob`) | not run |

## 4. Operational fit

| | Node 24 | Bun 1.4 | Deno 2.9 |
|---|---|---|---|
| Startup, `--version` (median of 10) | 131 ms | 71 ms | 106 ms |
| Tiny encrypt / decrypt, mock KAS + Keycloak (median of 5) | 274 / 311 ms | 206 / 280 ms | 307 / 304 ms |
| Compiled binary `--version` / encrypt / decrypt | (SEA untested) | 51 / 226 / 267 ms | 89 / 268 / 381 ms |
| Install | everywhere; current CLI target | npm `bun`, Homebrew, curl installer | npm `deno`, Homebrew, curl installer |
| Distribution | npm package (today) | npm, or `bun build --compile` (cross-targets) | npm via `npm:` specifier, or `deno compile` (cross-targets) |
| CI | `actions/setup-node` | `oven-sh/setup-bun` | `denoland/setup-deno` |
| Licence | MIT | MIT. Compiled binaries embed JavaScriptCore (LGPL-2.1), which matters if we ship them | MIT |
| Support posture | LTS lines, 24 in LTS until Apr 2028 | fast 1.x cadence, no LTS line. Oven (acquired by Anthropic, Dec 2025) | LTS channel available; Deno Land Inc. |

The tiny round trips are dominated by RSA-2048 keygen and the token fetch, so
small differences there are noise. Bun's startup advantage is about 60 ms.

## Recommendation

1. **Stay on Node.** Land the DSPX-5160 positional chunker. In the same
   release, **make the CLI bound decrypt prefetch** (follow-up ticket):
   either default `segmentBatchSize`/`maxConcurrentSegmentBatches` in
   `parseReadOptions`, or expose them as flags. 16 x 3 kept RSS under 1 GB at
   6+ GiB/s. The SDK's own bounded defaults (500 x 3 segments, up to ~3 GiB
   in flight) are too loose for a CLI. Without this, every runtime runs out of
   memory on a large TDF as soon as reads succeed.
2. **Bun: best-effort, not supported.** It is correct past 4 GiB and as fast
   as Node, but by itself it fixes nothing: the released CLI cannot decrypt
   anything under Bun. Merge the SDK negative-offset fix in this branch
   anyway, since it also helps SDK users who pass `Bun.file()` as a
   `file-browser` source. DSPX-5160's chunker avoids the bug on its own.
   Do not advertise `bunx` (it runs Node) or stdout piping (no backpressure).
   Reconsider "supported" once there is a CI job; xtest can now run the js
   shim under Bun with `XT_JS_RUNTIME=bun` (opentdf/tests, same branch).
3. **Deno: do not offer.** `openAsBlob` buffers the whole file, and WebCrypto
   AES-GCM is about 25x slower, so even a correct large decrypt is 13x slower
   than Node.
4. **Do not switch runtimes.** Switching would not fix the prefetch problem
   and would not beat Node + chunker meaningfully. It would also trade the Node
   LTS line for a runtime with Blob and stdout bugs we hit in one afternoon.

## Prototyped fixes in this branch

- `lib/src/seekable.ts` `fromBrowserFile` resolves negative offsets against
  `Blob.size` before calling `slice`, with unit tests in
  `lib/tests/mocha/unit/seekable.spec.ts`. This is a separate commit. It
  changes nothing on Node or in browsers.
- Not committed (scratch only): the FileHandle chunker (DSPX-5160 owns it) and
  the env-gated prefetch bound used for §3a.

## Still to verify (needs the platform)

- Real-KAS 64 GiB go/java decrypts through `--bench-scale`, run from the
  default tests checkout that has the unpushed `omwooook` change, with a dist
  dir pinned to Bun:

  ```bash
  cp -R sdk/js/dist/v0.20.0 sdk/js/dist/bun-v0.20.0 && echo bun > sdk/js/dist/bun-v0.20.0/.js-runtime
  uv run pytest test_benchmarks.py --bench --bench-scale 64GiB \
    --sdks "go@v0.38.1 java@<ver> js@bun-v0.20.0" --bench-out test-results/dspx-5162 -v
  ```

  Caveats:
  - Each new session gets a fresh attribute namespace, so the stamps
    won't match and go/java re-encrypt about 64 GiB each, overwriting their
    existing TDFs.
  - The js encrypt fails at the 64e9-byte limit.
  - A released 0.20.0 js decrypt fails under both Node and Bun. The js cell
    only means something with a CLI that includes DSPX-5160 plus bounded
    prefetch.
- EC / ML-KEM rewrap, assertions and DPoP under Bun and Deno.
- Linux x64 numbers (everything above is darwin-arm64).
