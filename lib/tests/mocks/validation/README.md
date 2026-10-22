# Go manifest-validation parity

`manifest-cases.json` records acceptance and rejection cases for the lax manifest schema used by
Go's `IsValidTdf`. All 42 expectations were verified against the actual OpenTDF Go SDK v0.35.0
function. Node and browser tests use this same corpus. Every archive generated for these cases
deliberately lacks a payload: Go's API validates the manifest, not the payload.

To recheck after a schema update, run the helper from an OpenTDF Go SDK module:

```sh
cd /path/to/platform/sdk
go run /path/to/web-sdk/lib/tests/mocks/validation/check-go.go \
  /path/to/web-sdk/lib/tests/mocks/validation/manifest-cases.json
```

The helper uses the Go SDK version selected by that module. Go is not required for the normal
TypeScript test suite. The vendored schema source/version is recorded in
`lib/src/manifest-lax.schema.ts`; preserve its validation semantics when refreshing it, including
intentionally permissive lax-schema cases.
