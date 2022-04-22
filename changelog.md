# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project
adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

# NEXT MAJOR RELEASE (6? migration to opentdf/client-web as single lib)

- Move `Errors` from tdf to top-level, consolidate and expose more.

## [v5.0.0] - 2022-04-13
- PLAT-1554: Moving tdf3js to opentdf, as final repo
- PLAT-1556: Moving OIDC to tdf3js
- PLAT-1638: Do webpack build process inline with naonTDF.js for future merge
- NO-REF: webpack hardcoded to dev due errors with CRA (dev-mode works fine)

## [v4.1.8](https://github.com/virtru/tdf3-js/compare/v4.1.7...v4.1.8) - 2021-??-??

- PLAT-1257 Increased coverage of typescript types
  - PLAT-1261 add utils types

## [v4.1.7](https://github.com/virtru/tdf3-js/compare/v4.1.6...v4.1.7) - 2021-09-02

- PLAT-1211: Add browser-based unit tests
- PLAT-1227: Enables es6 module import downstream
- PLAT-1257: Initial support for typscript type production
- PLAT-1134: Support decrypting large files (>= 4GiB)
- PLAT-1300: Buffer S3 Uploads

## [v4.1.6](https://github.com/virtru/tdf3-js/compare/v4.1.5...v4.1.6) - 2021-07-21

- NOREF promise added

## [v4.1.5](https://github.com/virtru/tdf3-js/compare/v4.1.4...v4.1.5) - 2021-07-08

- NOREF promise fix

## [v4.1.4](https://github.com/virtru/tdf3-js/compare/v4.1.3...v4.1.4) - 2021-07-08

- NOREF syntax change

## [v4.1.3](https://github.com/virtru/tdf3-js/compare/v4.1.2...v4.1.3) - 2021-07-08

- NOREF syntax change

## [v4.1.2](https://github.com/virtru/tdf3-js/compare/v4.1.1...v4.1.2) - 2021-07-02

- PLAT-1093: [Remote Storage](https://github.com/virtru/tdf3-js/pull/253)
  - Use StreamSaver to support streaming large file decrypts on the web.
  - Allow streaming to AWS S3 with multipart uploads.
  - Note this significantly increases the built artifact size, due to deps on streamsaver and AWS S3
    Client support.
- PLAT-1151: [Streaming Remote URL Decrypt](https://github.com/virtru/tdf3-js/pull/249)
  - Adds `setRemoteSource(url)` and corresponding `with` methods to `DecryptParamsBuilder`.
  - This allows decrypting files without copying them into memory, if the remote endpoint supports
    [`range` headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)
- PLAT-1096: [RCA Sources](https://github.com/virtru/tdf3-js/pull/254)
  - Added ‘RCA Source’ parameter to allow encrypting and decrypting with a Virtru, Inc. RCA link.

## [v4.1.1](https://github.com/virtru/tdf3-js/compare/v4.1.0...v4.1.1) - 2021-05-24

- PLAT-1106
  - more thrashing on this. Roll back 4.0.1, #235, change of binary`

## [v4.1.0](https://github.com/virtru/tdf3-js/compare/v4.0.1...v4.1.0) - 2021-05-07

### Removed

- PLAT-XXX
  - Removed test for virtru-specific 'user settings' backend.
  - Adds generic 'Entity Object' validation extension point.

## [v4.0.1](https://github.com/virtru/tdf3-js/compare/v4.0.0...v4.0.1) - 2021-04-23

### Fixed

- PLAT-1106: _patch_
  - Updates to UTF Compatible version of binary.js

## [v4.0.0](https://github.com/virtru/tdf3-js/compare/v3.4.7...v4.0.0) - 2021-02-18

### Removed

- PLAT-636: No longer tries to look up KAS public key directly; this was an undocumented part of the
  protocol, and has been replaced with the 'isDefault' setting on the EO. If you want to use another
  KAS, specify its public key as well. But as it stands the only supported KASes are those that are
  returned in an EO attribute. Also removes `getPublicKeyFromKeyAccessServer` helper method.
- PLAT-1009: Removes `tdf.write` and `read` methods, and `protocol` option in favor of `writeStream`
  and `readStream` and the `client` `encrypt` and `decrypt` methods

## [v3.4.7](https://github.com/virtru/tdf3-js/compare/v3.4.5...v3.4.7) - 2021-01-22

### fixed

- PLAT-978 Remove dependencies on lodash, bluebird, and also some inaccessible code

## [v3.4.5](https://github.com/virtru/tdf3-js/compare/v3.4.4...v3.4.5) - 2021-01-05

### fixed

- PLAT-964: Update axios to fix [vuln](https://www.npmjs.com/advisories/1594)

## [v3.4.4](https://github.com/virtru/tdf3-js/compare/v3.4.3...v3.4.4) - 2020-11-25

### fixed

- CORE-1911: added prepare script ([#222](https://github.com/virtru/tdf3-js/pull/222))

## [v3.4.3](https://github.com/virtru/tdf3-js/compare/v3.2.3...v3.4.3) - 2020-11-16

### fixed

- CORE-1911: transpile fix ([#220](https://github.com/virtru/tdf3-js/pull/220))
- PLAT-833: node-fore vuln ([#219](https://github.com/virtru/tdf3-js/pull/219))
- PLAT-773: File save api for browser ([#217](https://github.com/virtru/tdf3-js/pull/217))

## [v3.2.3](https://github.com/virtru/tdf3-js/compare/v3.2.2...v3.2.3) - 2019-08-14

### Added

- PLAT-704: Added prerelease and release script

## [v3.2.2](https://github.com/virtru/tdf3-js/compare/v3.2.1...v3.2.2)

### Fixed

- NO-REF: Allow auth plugins to modify endpoint URLs

## [v3.2.1](https://github.com/virtru/tdf3-js/compare/v3.1.3...v3.2.1) - 2019-06-29

### Changed

- Added `entityObjectEndpoint` parameter, to allow custom EAS endpoint names.
- Similarly, `kasEndpoint` is still used (to add Attributes), but the following KAS URIs can be
  specified:
  - `kasPublicKeyEndpoint`, a URI for loading the KAS public key, used in policy dataAttributes
  - `keyRewrapEndpoint`
  - `keyUpsertEndpoint`

### Added

- Adds missing `withOffline()` function to `EncryptParamsBuilder`, to match `setOffline` and
  `withOnline`
- PLAT-618: Attributes validation.

### Fixed

- PLAT-630: Correctly import babel runtime.
- PLAT-621: Don't update passed-by-reference objects in client constructor.

## [v3.1.3](https://github.com/virtru/tdf3-js/compare/v3.1.2...v3.1.3) - 2019-06-29

- PLAT-604: Fix HMAC hash calculation when using SJCL
  ([#202](https://github.com/virtru/tdf3-js/pull/202))

## [v3.1.2](https://github.com/virtru/tdf3-js/compare/v3.1.1...v3.1.2) - 2019-06-11

### Fixed

- PLAT-579: Fix some undefined variable errors ([#190](https://github.com/virtru/tdf3-js/pull/190))

## [v3.1.1](https://github.com/virtru/tdf3-js/compare/v3.1.0...v3.1.1) - 2019-06-09

### Fixed

- PLAT-564: Properly resolve some promises and catch/throw exceptions
  ([#189](https://github.com/virtru/tdf3-js/pull/189))

## [v3.1.0](https://github.com/virtru/tdf3-js/compare/v3.0.0...v3.1.0) - 2019-02-07

### Added

- PLAT-259: Can now set file mime type ([#174](https://github.com/virtru/tdf3-js/pull/174))
- Can read file details from the manifest.

### Fixed

- PLAT-353: Audit fix ([#184](https://github.com/virtru/tdf3-js/pull/184))
- PLAT-338: Errors now throw typed exceptions, and some formerly swallowed errors appropriately
  throw ([#177](https://github.com/virtru/tdf3-js/pull/177))
- Fixes bug where some references passed to builders could be modified during use.
  ([#171](https://github.com/virtru/tdf3-js/pull/171))
- PLAT-196: Fixes for manifest encoding ([#169](https://github.com/virtru/tdf3-js/pull/169),
  ([#167](https://github.com/virtru/tdf3-js/pull/167),
  ([#166](https://github.com/virtru/tdf3-js/pull/166))

## [v3.0.0](https://github.com/virtru/tdf3-js/compare/v2.2.8...v3.0.0) - 2019-02-07

- Libarchive support (for Cpp compat)
- [PLATFROM-110](https://github.com/virtru/tdf3-js/pull/158): Added offline mode support
- [PLATFROM-232](https://github.com/virtru/tdf3-js/pull/162): Node version updated
- [PLATFROM-196](https://github.com/virtru/tdf3-js/pull/160): tdf.html template changed to support
  policy send through iframe, changed embedded html manifest to base64
- [PLATFROM-59](https://github.com/virtru/tdf3-js/pull/165): Adds ability to get metadata from
  rewrap requests
- [PLAT-338](https://github.com/virtru/tdf3-js/pull/177)
  - Replace console statements with custom errors where able
  - Comment console statements and add TODO where unknown

## [v2.2.8](https://github.com/virtru/tdf3-js/compare/v2.2.7...v2.2.8) - 2019-10-10

- Update bluebird version

## [v2.2.7](https://github.com/virtru/tdf3-js/compare/v2.2.3...v2.2.7) - 2019-09-30

- Remove unused dependency `save-dev`
- Add audit to pipeline
- Update file-saver dependency
- Remove unused file-type dependency
- Properly escape HTML attributes

## [v2.2.3](https://github.com/virtru/tdf3-js/compare/v2.2.1...v2.2.3) - 2019-08-16

- Removing duplicated parameter for userSettings hmac.
- Removing content type header from userSettings fetch
- [NO-REF](https://github.com/virtru/tdf3-js/pull/120):
  - Change exports
  - Set `package.json` `main` to babel build
  - Use Node 10 and `npm ci`
  - Remove Webpack
  - Update Babel to v7

## [v2.2.1](https://github.com/virtru/tdf3-js/compare/v2.2.0...v2.2.1) - 2019-08-06

- Add and fix docs.

## [v2.2.0](https://github.com/virtru/tdf3-js/compare/v2.1.7...v2.2.0) - 2019-08-05

- Update the HTML template to include origin param on postMessage

## [v2.1.7](https://github.com/virtru/tdf3-js/compare/v2.1.6...v2.1.7) - 2019-08-04

- Minor documentation update.

## [v2.1.6](https://github.com/virtru/tdf3-js/compare/v2.1.5...v2.1.6) - 2019-08-02

- Default to application/text mime type.

## [v2.1.5](https://github.com/virtru/tdf3-js/compare/v2.1.3...v2.1.5) - 2019-08-02

- Default to html/text mime type.

## [v2.1.3](https://github.com/virtru/tdf3-js/compare/v2.1.2...v2.1.3) - 2019-08-01

- Fix merge issue.

## [v2.1.2](https://github.com/virtru/tdf3-js/compare/v2.1.1...v2.1.2) - 2019-08-01

- Fix decrypt for large files.

## [v2.1.1](https://github.com/virtru/tdf3-js/compare/v2.1.0...v2.1.1) - 2019-07-31

- Fix client.getPolicyId() for html files.
- Add arrayBuffer methods to builders.

## [v2.1.0](https://github.com/virtru/tdf3-js/compare/v2.0.0...v2.1.0) - 2019-07-31

- Add html support for encrypt/decrypt.
- [WS-9408](https://github.com/virtru/tdf3-js/pull/127): Added browser file implementations

## [v2.0.0](https://github.com/virtru/tdf3-js/compare/v1.3.8...v2.0.0) - 2019-07-29

**Migration Guide:** Change your import from:

```js
const TDF = require('tdf3-js');
```

to:

```js
const { TDF } = require('tdf3-js');
```

## [v1.3.8](https://github.com/virtru/tdf3-js/compare/v1.3.7...v1.3.8) - 2019-07-28

- [NOREF](https://github.com/virtru/tdf3-js/pull/125): Misc bugfixes and docs updates.

## [v1.3.7](https://github.com/virtru/tdf3-js/compare/v1.3.6...v1.3.7) - 2019-07-28

- [WS-9400](https://github.com/virtru/tdf3-js/pull/124): Documentation updates and misc additions.

## [v1.3.6](https://github.com/virtru/tdf3-js/compare/v1.3.5...v1.3.6) - 2019-07-26

- [WS-9396](https://github.com/virtru/tdf3-js/pull/120): Fix bug.

## [v1.3.5](https://github.com/virtru/tdf3-js/compare/v1.3.4...v1.3.5) - 2019-07-26

- [WS-9396](https://github.com/virtru/tdf3-js/pull/119): Apply stream backpressure for
  encrypt/decrypt output.

## [v1.3.4](https://github.com/virtru/tdf3-js/compare/v1.3.3...v1.3.4) - 2019-07-24

- [NO-REF](https://github.com/virtru/tdf3-js/pull/114): Replace `Binary` with `UInt8Array` for
  browsers

## [v1.3.3](https://github.com/virtru/tdf3-js/compare/v1.3.2...v1.3.3) - 2019-07-21

- [WS-9385](https://github.com/virtru/tdf3-js/pull/115): Update documentation for public JSDoc SDK
  docs.

## [v1.3.2](https://github.com/virtru/tdf3-js/compare/v1.3.1...v1.3.2) - 2019-07-19

- [NOREF](https://github.com/virtru/tdf3-js/pull/112): Rename tdf-stream methods.

## [v1.3.1](https://github.com/virtru/tdf3-js/compare/v1.3.0...v1.3.1) - 2019-07-18

- [NOREF](https://github.com/virtru/tdf3-js/pull/110): Bugfix for EncryptParamsBuilder. Update
  changelog.
- NOREF ([#109](https://github.com/virtru/tdf3-js/pull/109)): _patch_
  - Changed promisify method so as not to break IE11
- NOREF ([#107](https://github.com/virtru/tdf3-js/pull/107)): _patch_
  - Chunks are now encrypted with unique IVs every time

## [v1.3.0](https://github.com/virtru/tdf3-js/compare/v1.2.3...v1.3.0)- 2019-07-17

- [NOREF](https://github.com/virtru/tdf3-js/pull/108):
  - Rename Dissem to UsersWithAccess.
  - Remove offline methods from params builder (not supported for launch).
  - Introduce PlaintextStream and TDFCiphertextStream.
  - Add helper methods for writing to stream to file, string, and node buffer.
- [NOREF](https://github.com/virtru/tdf3-js/pull/107): Chunks are now encrypted with unique IVs
  every time

## [v1.2.3](https://github.com/virtru/tdf3-js/compare/v1.2.2...v1.2.3) - 2019-07-02

- [NOREF](https://github.com/virtru/tdf3-js/pull/103): Reverted the transpilation code from 1.2.2

## [v1.2.2](https://github.com/virtru/tdf3-js/compare/v1.2.1...v1.2.2) - 2019-06-28

- [NOREF-policy-upsert-fix](https://github.com/virtru/tdf3-js/pull/101): Remove integration tests
  and creds.
- [NOREF](https://github.com/virtru/tdf3-js/pull/102): Asked TDF3-js to provide it's transpiled
  version to libraries that use it.

## [v1.2.1](https://github.com/virtru/tdf3-js/compare/v1.2.0...v1.2.1) - 2019-06-26

### Changed

- [NOREF-policy-upsert-fix](https://github.com/virtru/tdf3-js/pull/99): Fixed policy upsert logic
  such that the full TDF3 policy is synced on upsert

- [WS-9100/WS-8962 #93](https://github.com/virtru/tdf3-js/pull/93): Added support for default
  attributes

## v0.1.1 - 2019-04-26

### Changed

- [WS-9033](https://github.com/virtru/tdf3-js/pull/78): Patch for FF stream decrypt, write in
  browser, defaults. Added CLI

## v0.1.0 - 2019-04-19

### Changed

- [WS-8969](https://github.com/virtru/tdf3-js/pull/77): Added lazy sync capabilities
