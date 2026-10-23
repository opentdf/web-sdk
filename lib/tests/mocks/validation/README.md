# Go manifest-validation parity

`manifest-cases.ts` records 42 acceptance and rejection cases for the lax schema used by Go's
`IsValidTdf`. Node and browser tests import the same module without filesystem access.
`archiveParityCases()` adds four duplicate-manifest archives covering both supported names and both
entry orders, plus two BOM-prefixed manifest archives that must be rejected.

The separately exported `experimentalCases` covers `mlkem-wrapped` key access in
Node and browser tests.

To compare byte-identical archives with Go, first export the TypeScript fixtures:

```sh
cd /path/to/web-sdk/lib
npm run build
node tests/mocks/validation/export-go-cases.mjs > /tmp/tdf-validation-cases.json
```

Run the verifier from an OpenTDF Go SDK module (verified with v0.35.0):

```sh
cd /path/to/platform/sdk
go run /path/to/web-sdk/lib/tests/mocks/validation/check-go.go \
  /tmp/tdf-validation-cases.json
```

Go is not required for the normal TypeScript test suite. The schema source/version is recorded in
`lib/src/manifest-lax.schema.ts`; preserve its validation semantics when refreshing it, including
intentionally permissive lax-schema cases.

Once the cross-SDK validity suite in opentdf/tests (DSPX-5349) lands, this corpus and the Go
verifier can shrink to a smoke test.
