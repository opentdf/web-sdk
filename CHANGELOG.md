# Changelog

## [0.15.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.14.0...sdk-v0.15.0) (2026-04-22)


### Features

* **sdk:** add ergonomic Resource constructors for authorization ([#921](https://github.com/opentdf/web-sdk/issues/921)) ([a14b777](https://github.com/opentdf/web-sdk/commit/a14b7771021271e6648d331fbd345dd89bcf13b4))
* **sdk:** add segment batch size and max concurrent segment batches options ([#920](https://github.com/opentdf/web-sdk/issues/920)) ([376c780](https://github.com/opentdf/web-sdk/commit/376c780d17355053348a832006bcdd90bddb00e2))
* **sdk:** namespace EntityIdentifier helpers under EntityIdentifiers ([#916](https://github.com/opentdf/web-sdk/issues/916)) ([d0ab115](https://github.com/opentdf/web-sdk/commit/d0ab11560a9f493b7b92fdf04408263fdac97734))


### Bug Fixes

* **ci:** remove redundant npm install in dev-artifact workflow ([#913](https://github.com/opentdf/web-sdk/issues/913)) ([015176c](https://github.com/opentdf/web-sdk/commit/015176cb56d9155b6b4a050da6688f51021365f7))

## [0.14.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.13.0...sdk-v0.14.0) (2026-04-09)


### Features

* **sdk:** add EntityIdentifier convenience constructors ([#911](https://github.com/opentdf/web-sdk/issues/911)) ([0bbe549](https://github.com/opentdf/web-sdk/commit/0bbe54997f8ef00e9d75a28a115ed85c54ad5a15))
* **sdk:** add TokenProvider factory functions for common OIDC flows ([#906](https://github.com/opentdf/web-sdk/issues/906)) ([7627b1e](https://github.com/opentdf/web-sdk/commit/7627b1e66664c4c314fa1fe41f37023e53b71df3))
* **sdk:** deprecate AuthProvider in favor of Interceptor pattern ([#899](https://github.com/opentdf/web-sdk/issues/899)) ([1be800e](https://github.com/opentdf/web-sdk/commit/1be800ead70283a4624fb65030c1a941b6beed71))


### Bug Fixes

* **ci:** allow main scope in PR title validation ([#912](https://github.com/opentdf/web-sdk/issues/912)) ([14152c4](https://github.com/opentdf/web-sdk/commit/14152c4a4e662c66d805db811a8e9f21e89b4205))
* **sdk:** bump lodash from 4.17.23 to 4.18.1 in /lib ([#909](https://github.com/opentdf/web-sdk/issues/909)) ([3f1799c](https://github.com/opentdf/web-sdk/commit/3f1799c3892dd850cf54ab0f00f76f3545e106c3))
* **sdk:** gate signingKey check on dpopEnabled in withCreds ([#898](https://github.com/opentdf/web-sdk/issues/898)) ([74e350a](https://github.com/opentdf/web-sdk/commit/74e350a32c06b99f65a09377d027fecade15010d))

## [0.13.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.12.0...sdk-v0.13.0) (2026-03-27)


### Bug Fixes

* **sdk:** bump picomatch in /lib ([#893](https://github.com/opentdf/web-sdk/issues/893)) ([29fb0be](https://github.com/opentdf/web-sdk/commit/29fb0be5fc7c0c0811a94ec48c965e08042160fb))
* **sdk:** Only use crypto service randomBytes where necessary ([#889](https://github.com/opentdf/web-sdk/issues/889)) ([1818a74](https://github.com/opentdf/web-sdk/commit/1818a74a3529cd3f681410c15c2895412178b084))

## [0.12.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.11.0...sdk-v0.12.0) (2026-03-18)


### Bug Fixes

* **ci:** use 'sdk' scope in release-please PR title pattern ([#867](https://github.com/opentdf/web-sdk/issues/867)) ([a1acca2](https://github.com/opentdf/web-sdk/commit/a1acca2ad77db1d043fecb9a2cf6b66868321645))
* **sdk:** correct disableDPoP flag and add eager DPoP key binding ([#883](https://github.com/opentdf/web-sdk/issues/883)) ([bfb23f8](https://github.com/opentdf/web-sdk/commit/bfb23f84ded2ec9efb05e2a1a278eebed7b5dcfa))
* **sdk:** update lib README with current SDK usage patterns ([#886](https://github.com/opentdf/web-sdk/issues/886)) ([8f1c0ec](https://github.com/opentdf/web-sdk/commit/8f1c0ec5def6309996d9a8548bef77887c22e1df))

## [0.11.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.10.0...sdk-v0.11.0) (2026-03-17)


### Bug Fixes

* **ci:** update tests to cover sdk-v* tag format for npm latest dist-tag ([#868](https://github.com/opentdf/web-sdk/issues/868)) ([4d9058d](https://github.com/opentdf/web-sdk/commit/4d9058d7a78b9951675849b0fb27585e25876ae7))
* **sdk:** await sleep in retry backoff; fix CI deliver and dev-artifact ([#858](https://github.com/opentdf/web-sdk/issues/858)) ([f14d6eb](https://github.com/opentdf/web-sdk/commit/f14d6eb09605e65855b69bed39dbbd1241276d63))

## [0.10.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.9.0...sdk-v0.10.0) (2026-03-10)


### Features

* **sdk:** add createTDF alias for createZTDF, deprecate createZTDF ([#855](https://github.com/opentdf/web-sdk/issues/855)) ([84503b0](https://github.com/opentdf/web-sdk/commit/84503b06b7220001aaa46185380ce4a140c6dfc9))
* **sdk:** DSPX-2418 add attribute discovery methods ([#841](https://github.com/opentdf/web-sdk/issues/841)) ([06c5964](https://github.com/opentdf/web-sdk/commit/06c596415a4a3600e9401fce2f7658b9d23190e1))
* **sdk:** Encapsulate all crypto in cryptoservice, make it pluggable ([#835](https://github.com/opentdf/web-sdk/issues/835)) ([6ab17cc](https://github.com/opentdf/web-sdk/commit/6ab17cc000481b0845378b5fb44c004b05d393c4))


### Bug Fixes

* **sdk:** bump minimatch in /lib ([#850](https://github.com/opentdf/web-sdk/issues/850)) ([ecbac8f](https://github.com/opentdf/web-sdk/commit/ecbac8f5d7ea4866b8f126e8f53ac81f102b9c07))
* **sdk:** bump qs from 6.14.1 to 6.14.2 in /lib ([#839](https://github.com/opentdf/web-sdk/issues/839)) ([44afd7d](https://github.com/opentdf/web-sdk/commit/44afd7d90f0f10aa29bc177ee171454c6537de77))
* **sdk:** bump rollup from 4.25.0 to 4.59.0 in /lib ([#848](https://github.com/opentdf/web-sdk/issues/848)) ([27dbcbc](https://github.com/opentdf/web-sdk/commit/27dbcbc481073df22791fe306ded0be86d88d171))
* Update curve name from P-512 to P-521 in crypto utilities ([#837](https://github.com/opentdf/web-sdk/issues/837)) ([a3c440c](https://github.com/opentdf/web-sdk/commit/a3c440c667194bcca97c9b3fb2ad9d3cc7d23fd3))

## [0.9.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.8.0...sdk-v0.9.0) (2026-01-28)


### ⚠ BREAKING CHANGES

* remove NanoTDF support ([#791](https://github.com/opentdf/web-sdk/issues/791))

### Features

* remove NanoTDF support ([#791](https://github.com/opentdf/web-sdk/issues/791)) ([6a87956](https://github.com/opentdf/web-sdk/commit/6a87956e9982eb6c3198cfdfa19651bb8d446d70))
* **sdk:** Pull kas keys from definitions and namespaces. ([#808](https://github.com/opentdf/web-sdk/issues/808)) ([28eb417](https://github.com/opentdf/web-sdk/commit/28eb417a1f1beaf030c9d6bd069249d0ab94a53d))


### Bug Fixes

* all vulnerabilities and update tooling ([#812](https://github.com/opentdf/web-sdk/issues/812)) ([be7e4ae](https://github.com/opentdf/web-sdk/commit/be7e4ae81b3cd7661bc66453b60ade76dd71a9ff))
* **sdk:** bump lodash from 4.17.21 to 4.17.23 in /lib ([#810](https://github.com/opentdf/web-sdk/issues/810)) ([abc3acd](https://github.com/opentdf/web-sdk/commit/abc3acd4007da8c2e60efa9be32f89ed43ebadd8))

## [Unreleased]

### Removed

- **BREAKING**: Removed NanoTDF support. The NanoTDF format and all related APIs
  (`NanoTDFClient`, `NanoTDFDatasetClient`, `createNanoTDF()`, `createNanoTDFCollection()`,
  `NanoTDFReader`, `@opentdf/sdk/nano` export) have been removed.
  Use ZTDF format via `createZTDF()` instead.

### Changed

- Renamed `nanotdf-crypto/` to `crypto/` - internal cryptographic primitives directory.

## [0.8.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.7.0...sdk-v0.8.0) (2026-01-14)


### Features

* **ci:** add npm provenance support for package publishing ([#797](https://github.com/opentdf/web-sdk/issues/797)) ([4d342ce](https://github.com/opentdf/web-sdk/commit/4d342ce714759a62cd6a51f341adf1bbae72b5c4))
* DSPX-2234-key-management-and-obligation-client-stub ([#793](https://github.com/opentdf/web-sdk/issues/793)) ([e7d56b3](https://github.com/opentdf/web-sdk/commit/e7d56b3407ddbfa5d1e2a19dd8609beb8d757b0e))


### Bug Fixes

* **cli:** bump glob from 10.4.5 to 10.5.0 in /cli ([#787](https://github.com/opentdf/web-sdk/issues/787)) ([e00a909](https://github.com/opentdf/web-sdk/commit/e00a90999afda524529d2f0d01d039f2e8029ef0))
* **sdk:** bump qs and body-parser in /lib ([#789](https://github.com/opentdf/web-sdk/issues/789)) ([8e342f9](https://github.com/opentdf/web-sdk/commit/8e342f961eb7056db04aa7d976322a2fc55395e2))

## [0.7.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.6.0...sdk-v0.7.0) (2026-01-09)


### Features

* Assertion verification JWK and X.509 ([#790](https://github.com/opentdf/web-sdk/issues/790)) ([f5a8f5e](https://github.com/opentdf/web-sdk/commit/f5a8f5e5d6bc5794955451a50bdb4ec2755dee97))


### Bug Fixes

* **sdk:** bump glob in /lib ([#785](https://github.com/opentdf/web-sdk/issues/785)) ([aadafd4](https://github.com/opentdf/web-sdk/commit/aadafd47b7a430ca886e21d00f0735299c05a46a))

## [0.6.0](https://github.com/opentdf/web-sdk/compare/sdk-v0.5.0...sdk-v0.6.0) (2025-10-30)


### Features

* **ci:** Add a workflow to update the generated code for new protocol/go versions ([#767](https://github.com/opentdf/web-sdk/issues/767)) ([c9d5f21](https://github.com/opentdf/web-sdk/commit/c9d5f21f89c7a523a524b8da3345c9b0c69743dc))
* **sdk:** Add requiredObligations to the PermissionDeniedError ([#781](https://github.com/opentdf/web-sdk/issues/781)) ([9cd7b44](https://github.com/opentdf/web-sdk/commit/9cd7b44b406e96d00c8bb17d3783bc0652b7fe2f))
* **sdk:** Move to rewrap v2 request/response format ([#774](https://github.com/opentdf/web-sdk/issues/774)) ([e7718d5](https://github.com/opentdf/web-sdk/commit/e7718d583d2cd1b770afd4bb0b3159d5a05ba21c))


### Bug Fixes

* **sdk:** Additional comments and cleanup of Rewrap V2 code ([#780](https://github.com/opentdf/web-sdk/issues/780)) ([bb29962](https://github.com/opentdf/web-sdk/commit/bb299623d82572509b6a59557a97e5cca5ad6740))

## [0.5.0](https://github.com/opentdf/web-sdk/compare/sdk/v0.4.0...sdk-v0.5.0) (2025-10-17)


### Features

* add system metadata assertion ([#630](https://github.com/opentdf/web-sdk/issues/630)) ([922965c](https://github.com/opentdf/web-sdk/commit/922965c25c0a63b616dc833275152c4c55148ac3))
* Certificates & Obligations ([#755](https://github.com/opentdf/web-sdk/issues/755)) ([688c304](https://github.com/opentdf/web-sdk/commit/688c30490e21d6c2080c187f8915c3eece41251d))
* Get Namespace ([#756](https://github.com/opentdf/web-sdk/issues/756)) ([5b8ef25](https://github.com/opentdf/web-sdk/commit/5b8ef2518f16fbb69cb1d7b5e0297eb87f8e076c))
* **sdk:** initial obligations support in rewrap flow ([#748](https://github.com/opentdf/web-sdk/issues/748)) ([0361361](https://github.com/opentdf/web-sdk/commit/03613617974982fe39cc7ac1362a17f843a40e63))


### Bug Fixes

* `signingKey` should not be part of the computed hash ([#696](https://github.com/opentdf/web-sdk/issues/696)) ([b763278](https://github.com/opentdf/web-sdk/commit/b7632783b17413393db3ff2ac49a2ad9201ed8ef))
* **sdk:** Fix new API not setting nano attributes ([#679](https://github.com/opentdf/web-sdk/issues/679)) ([f0d9719](https://github.com/opentdf/web-sdk/commit/f0d97196ab258122fe9a07b7d7895017299a46c2))
* SEC-4653 prevent ReDoS vulnerability in HTML payload unwrapping regex ([#686](https://github.com/opentdf/web-sdk/issues/686)) ([09d0360](https://github.com/opentdf/web-sdk/commit/09d036055a4eea621d182f04b706fae6dc78c195))

## [0.4.0](https://github.com/opentdf/web-sdk/compare/v0.3.2...v0.4.0) (2025-06-26)


### Features

* Add initial Dependency Review configuration ([#587](https://github.com/opentdf/web-sdk/issues/587)) ([8f9d343](https://github.com/opentdf/web-sdk/commit/8f9d34373da1d5d01cfb58c064c108fac8503dfe))
* Assertion signing key handling and verification in the CLI ([#409](https://github.com/opentdf/web-sdk/issues/409)) ([242150b](https://github.com/opentdf/web-sdk/commit/242150b69d2fd428ed4c6cab4d27b1d258ebe11a))
* **cli:** Adds --allowList parameter to cli ([#328](https://github.com/opentdf/web-sdk/issues/328)) ([297cec6](https://github.com/opentdf/web-sdk/commit/297cec667ef3e87263ab9e58fae1482750009156))
* **cli:** Adds `--policyBinding ecdsa` option ([#352](https://github.com/opentdf/web-sdk/issues/352)) ([4e54c0d](https://github.com/opentdf/web-sdk/commit/4e54c0d6d9cd6b6d1c05296cf954431970509367))
* **cli:** Enables experimental ec in KAOs ([#457](https://github.com/opentdf/web-sdk/issues/457)) ([203563c](https://github.com/opentdf/web-sdk/commit/203563ce800f13bcf2efded7e499efae46debb99))
* **cli:** Pass the platform url on decrypt, add the platform kas to the allowlist when fetching ([#565](https://github.com/opentdf/web-sdk/issues/565)) ([5afd0d0](https://github.com/opentdf/web-sdk/commit/5afd0d058f9111a8fef420ec560e0dcf4fde6007))
* **core:** Adds kao.schemaVersion ([#416](https://github.com/opentdf/web-sdk/issues/416)) ([7925669](https://github.com/opentdf/web-sdk/commit/7925669cd6131e252147df126c6e1c0bedc3e0d0))
* **core:** KID in NanoTDF ([#325](https://github.com/opentdf/web-sdk/issues/325)) ([6d01eff](https://github.com/opentdf/web-sdk/commit/6d01eff5bdf2f9fde688b3dab4e57470fb255c88))
* export connect rpc generated platform from package.json ([#610](https://github.com/opentdf/web-sdk/issues/610)) ([cbd8a10](https://github.com/opentdf/web-sdk/commit/cbd8a10eb5e277c40b04e894f62bb3f53aa2a483))
* get kas public key from base key ([#623](https://github.com/opentdf/web-sdk/issues/623)) ([5bde0a1](https://github.com/opentdf/web-sdk/commit/5bde0a10e82b3c431d801aa683d42b7911aed882))
* lets nanoTDF client take options instead ([#278](https://github.com/opentdf/web-sdk/issues/278)) ([048bd30](https://github.com/opentdf/web-sdk/commit/048bd3063450dd56e6d9b749f9efd0fca451c6ee))
* **lib:** Bump for EC feature ([#452](https://github.com/opentdf/web-sdk/issues/452)) ([6178877](https://github.com/opentdf/web-sdk/commit/6178877c8a307fe461f3ce348cb63a7204ccda45))
* **lib:** generate ts code from platform protos ([#280](https://github.com/opentdf/web-sdk/issues/280)) ([d88c612](https://github.com/opentdf/web-sdk/commit/d88c612a8d7670ba16828c77662fe4f21dc8258c))
* **lib:** Load abac config from policy service ([#351](https://github.com/opentdf/web-sdk/issues/351)) ([48b2442](https://github.com/opentdf/web-sdk/commit/48b24426c26ff56e0edb7d2e78eda34e844be135))
* **lib:** offline abac KAO configuration ([#349](https://github.com/opentdf/web-sdk/issues/349)) ([6eb70c1](https://github.com/opentdf/web-sdk/commit/6eb70c1fdfc4e18308dbb898594fa773e1f2c7a8))
* **lib:** Updated error types ([#362](https://github.com/opentdf/web-sdk/issues/362)) ([7fb29c5](https://github.com/opentdf/web-sdk/commit/7fb29c5ef519720f7d2c9c8e488e6246743e8d1c))
* **sdk:** Adds OpenTDF.open method ([#485](https://github.com/opentdf/web-sdk/issues/485)) ([6ba9044](https://github.com/opentdf/web-sdk/commit/6ba90445b263bf8084b421faab742c93688446dd))
* **sdk:** Adds opts for collection cache ([#411](https://github.com/opentdf/web-sdk/issues/411)) ([47a5287](https://github.com/opentdf/web-sdk/commit/47a528718dbffe999894ecdae904930919fcc9ed))
* **sdk:** Allow custom KAO array templates ([#307](https://github.com/opentdf/web-sdk/issues/307)) ([fd1b386](https://github.com/opentdf/web-sdk/commit/fd1b38677b309083a54c0818b316d9e39d7aa649))
* **sdk:** Allows skipping verification ([#371](https://github.com/opentdf/web-sdk/issues/371)) ([8529461](https://github.com/opentdf/web-sdk/commit/85294612fb6886fa4da6cf4d070c54168ed634de))
* **sdk:** Assertion support ([#350](https://github.com/opentdf/web-sdk/issues/350)) ([10ff5c7](https://github.com/opentdf/web-sdk/commit/10ff5c7b940a1287cb2dfbbaeee50ba58d0b85a7))
* **sdk:** connect rpc client export ([#545](https://github.com/opentdf/web-sdk/issues/545)) ([92de145](https://github.com/opentdf/web-sdk/commit/92de1451cc18c9385d35331dafa4b078e7a1736b))
* **sdk:** ec-wrapped key support ([#422](https://github.com/opentdf/web-sdk/issues/422)) ([9d4eab4](https://github.com/opentdf/web-sdk/commit/9d4eab46de11bbbe8bc660149fad245853d18e94))
* **sdk:** Export AttributeObject and others ([#487](https://github.com/opentdf/web-sdk/issues/487)) ([3d45ecf](https://github.com/opentdf/web-sdk/commit/3d45ecfa07f27ba62d47a416a056481a7b5d859e))
* **sdk:** get KASes list from platform when allowedKases list is not passed ([#557](https://github.com/opentdf/web-sdk/issues/557)) ([598c39f](https://github.com/opentdf/web-sdk/commit/598c39f2bccb4eb2a0f19143cf1d47d07bd65232))
* **sdk:** remove hex encoding for segment hash ([#397](https://github.com/opentdf/web-sdk/issues/397)) ([ec4a55a](https://github.com/opentdf/web-sdk/commit/ec4a55a2890375b7dd5be61dafa93b505e54be7b))
* **sdk:** sdk to use connect rpc calls ([#596](https://github.com/opentdf/web-sdk/issues/596)) ([f8e54e5](https://github.com/opentdf/web-sdk/commit/f8e54e5ff0a5775a2e7c3e487d1f16b227231583))
* **sdk:** Updates to jose 6.x ([#449](https://github.com/opentdf/web-sdk/issues/449)) ([9667747](https://github.com/opentdf/web-sdk/commit/966774769a674d65b5a32e002687f08104844732))


### Bug Fixes

* add ignoreAllowList flag ([#331](https://github.com/opentdf/web-sdk/issues/331)) ([29a9b82](https://github.com/opentdf/web-sdk/commit/29a9b82e98bd99c95a59288949ff182103c09a05))
* Assertion verification key input ([#412](https://github.com/opentdf/web-sdk/issues/412)) ([5be9bb1](https://github.com/opentdf/web-sdk/commit/5be9bb11bb73b5859ea7f18a6309dd70e93dc94a))
* **audit:** npm audit fix ([#304](https://github.com/opentdf/web-sdk/issues/304)) ([ca2dddd](https://github.com/opentdf/web-sdk/commit/ca2dddd189970ed368e1f9213a15e3eaafb3dde3))
* **audit:** npm audit fix ([#318](https://github.com/opentdf/web-sdk/issues/318)) ([bc574f7](https://github.com/opentdf/web-sdk/commit/bc574f7878e5583b90ca5bab2f80a1a111df7b99))
* Changes to make regex patterns more efficient, accurate and simpler ([#376](https://github.com/opentdf/web-sdk/issues/376)) ([2fe2c43](https://github.com/opentdf/web-sdk/commit/2fe2c43ee3c481f6f40eba11a50e0ab8155ea024))
* **ci:** Get platform_roundtrip working again ([#413](https://github.com/opentdf/web-sdk/issues/413)) ([6ca50e6](https://github.com/opentdf/web-sdk/commit/6ca50e6f3b2d945c98993190784a78e960438d8f))
* **ci:** ignore auto-formatting of proto-generated files ([#296](https://github.com/opentdf/web-sdk/issues/296)) ([30fb685](https://github.com/opentdf/web-sdk/commit/30fb6858d16ed488e6e5eed2ee38700782261d61))
* **ci:** use keycloack docker ([#555](https://github.com/opentdf/web-sdk/issues/555)) ([dc4e48e](https://github.com/opentdf/web-sdk/commit/dc4e48e571b3c3fcd0f29c6e26c4814d1e0acc61))
* **cli:** Better errors and properly set exit code in more cases ([#418](https://github.com/opentdf/web-sdk/issues/418)) ([11ad526](https://github.com/opentdf/web-sdk/commit/11ad526ed29f8c334d1d048dacd8302795ce5589))
* **cli:** Enables concurrent rewrap in cli ([#391](https://github.com/opentdf/web-sdk/issues/391)) ([ab40664](https://github.com/opentdf/web-sdk/commit/ab40664e5b0fb26b9056066fdb6fa2224ffd74a5))
* **client:** Normalize allowlist to origins ([#321](https://github.com/opentdf/web-sdk/issues/321)) ([ac1f634](https://github.com/opentdf/web-sdk/commit/ac1f634df2db559f895ac1317dad8c5af14da680))
* **core:** npm audit fix ([#380](https://github.com/opentdf/web-sdk/issues/380)) ([496f07c](https://github.com/opentdf/web-sdk/commit/496f07ca7029ded39bd0c71a59f1c7220dd419c1))
* **docs:** Update README.md - remove outdated / incorrect quickstart links / ins… ([#301](https://github.com/opentdf/web-sdk/issues/301)) ([2dbca15](https://github.com/opentdf/web-sdk/commit/2dbca15deb0b590055c70a4ba93b828cd27ee3d1))
* **dpop:** respect dpop disabled flag in oidc access token class methods ([#299](https://github.com/opentdf/web-sdk/issues/299)) ([24319f7](https://github.com/opentdf/web-sdk/commit/24319f72c70ee30a1a242c0e37d0d775eca91604))
* keySplitInfo Promise.any Promise.all ([#379](https://github.com/opentdf/web-sdk/issues/379)) ([c6cdbef](https://github.com/opentdf/web-sdk/commit/c6cdbefc5c2cffda0c8a70972ee115e60112bfa4))
* **lib:** Adds a 10 MiB cap to manifest size ([#353](https://github.com/opentdf/web-sdk/issues/353)) ([e775ba5](https://github.com/opentdf/web-sdk/commit/e775ba5b7d9fca7f91ce9a50650d4e69a03711bc))
* **logs:** Improves on decrypt unsafe fail ([#303](https://github.com/opentdf/web-sdk/issues/303)) ([4efa118](https://github.com/opentdf/web-sdk/commit/4efa118a0d307ea08d6b941670d610d82cb4af50))
* **nano:** Allow padding of kids ([#338](https://github.com/opentdf/web-sdk/issues/338)) ([e1ae891](https://github.com/opentdf/web-sdk/commit/e1ae8912617869e298325df57f4888e5fe3a14a6))
* **nano:** ecdsa policy binding support for encrypt ([#346](https://github.com/opentdf/web-sdk/issues/346)) ([031bbb7](https://github.com/opentdf/web-sdk/commit/031bbb7154a638c3b0c55ea58369af3182414f94))
* **nano:** resource locator kid parse issue ([#330](https://github.com/opentdf/web-sdk/issues/330)) ([4eef553](https://github.com/opentdf/web-sdk/commit/4eef553dc5a779637c1ea8567b27d411524643f3))
* **nano:** Store kid ([#334](https://github.com/opentdf/web-sdk/issues/334)) ([63721f6](https://github.com/opentdf/web-sdk/commit/63721f634bb1bb4b3cfd91343eff67fdabd7e603))
* Remove environment logging in vite.config.ts ([#373](https://github.com/opentdf/web-sdk/issues/373)) ([d1e0a45](https://github.com/opentdf/web-sdk/commit/d1e0a4538e2f5ba58d42dbad3754131b6a533612))
* Rewrap response handling typo ([#372](https://github.com/opentdf/web-sdk/issues/372)) ([5add5aa](https://github.com/opentdf/web-sdk/commit/5add5aa1be96abf08c15573080e8e8e537e939f8))
* **sdk:** bump koa from 2.15.4 to 2.16.1 in /lib ([#534](https://github.com/opentdf/web-sdk/issues/534)) ([57c6d69](https://github.com/opentdf/web-sdk/commit/57c6d69862c577d5b459cb57edf8865f87c75dab))
* **sdk:** bump uuid from 11.0.5 to 11.1.0 in /lib ([#432](https://github.com/opentdf/web-sdk/issues/432)) ([3898e45](https://github.com/opentdf/web-sdk/commit/3898e4513ade1a1c5a1799ef58bef249f02bb14f))
* **sdk:** Bump version no. to 0.3.2 ([#536](https://github.com/opentdf/web-sdk/issues/536)) ([5924bc9](https://github.com/opentdf/web-sdk/commit/5924bc9f3cdb694b8f1be8ddd53f1b59e4f96115))
* **sdk:** calculate the length of ecdsa binding ([#327](https://github.com/opentdf/web-sdk/issues/327)) ([69e0a81](https://github.com/opentdf/web-sdk/commit/69e0a8156f747c27aa185f0cb22498b0a9ed8e53))
* **sdk:** Disable concurrency on rewrap ([#388](https://github.com/opentdf/web-sdk/issues/388)) ([beb3c06](https://github.com/opentdf/web-sdk/commit/beb3c0644683549b0c6eaf6858b27c6222512e35))
* **sdk:** Don't set schemaV in older target specs ([#531](https://github.com/opentdf/web-sdk/issues/531)) ([eed7545](https://github.com/opentdf/web-sdk/commit/eed7545fca60e94123697adca151b470c1719be4))
* **sdk:** Enable support for more KAS key types ([#624](https://github.com/opentdf/web-sdk/issues/624)) ([35c9777](https://github.com/opentdf/web-sdk/commit/35c977767f6b7291d2b6d96e803cac45d71ddcd2))
* **sdk:** Fix assertion output for legacy mode ([#533](https://github.com/opentdf/web-sdk/issues/533)) ([d54d777](https://github.com/opentdf/web-sdk/commit/d54d777ada207d82c99672dd9ab9d82b1a3fb8ce))
* **sdk:** Fix for queries to older platforms ([#570](https://github.com/opentdf/web-sdk/issues/570)) ([f6ccc10](https://github.com/opentdf/web-sdk/commit/f6ccc106747027e8e01f4074d270402f047e464a))
* **sdk:** Fixes generating ztdf 4.2.2 output ([#530](https://github.com/opentdf/web-sdk/issues/530)) ([ab42e5a](https://github.com/opentdf/web-sdk/commit/ab42e5a1f8463d6cbc18695f53c56b3403950fdd))
* **sdk:** Let pools take callables. ([#390](https://github.com/opentdf/web-sdk/issues/390)) ([75ca10c](https://github.com/opentdf/web-sdk/commit/75ca10c018dc61fdc9f3892c40a6b14daed2f4c2))
* **sdk:** Lets new API set nano binding type ([#455](https://github.com/opentdf/web-sdk/issues/455)) ([26879ef](https://github.com/opentdf/web-sdk/commit/26879ef9e81dbe5b8daff065c2ad7ef433072669))
* **sdk:** npm audit fix ([#410](https://github.com/opentdf/web-sdk/issues/410)) ([840fd29](https://github.com/opentdf/web-sdk/commit/840fd297a419d5fa402e68bed04b45698d2d5214))
* **sdk:** Remove AttributeSet ([#489](https://github.com/opentdf/web-sdk/issues/489)) ([fa5a98d](https://github.com/opentdf/web-sdk/commit/fa5a98dcceacd0c92554c5822780a8300f2b29d7))
* **sdk:** Remove stray call to node:Buffer ([#365](https://github.com/opentdf/web-sdk/issues/365)) ([f851c02](https://github.com/opentdf/web-sdk/commit/f851c026455c6d6389c02f11cef478c2e08345c4))
* **sdk:** Removes ntdf version header ([#488](https://github.com/opentdf/web-sdk/issues/488)) ([f657181](https://github.com/opentdf/web-sdk/commit/f657181c63a23a83876b689d42b9910d9937420a))
* **sdk:** Sets schemaVersion, not tdf_spec_version ([#414](https://github.com/opentdf/web-sdk/issues/414)) ([74d326b](https://github.com/opentdf/web-sdk/commit/74d326b940049e9e9943648cd71ade723d16522d))
* **sdk:** support hex encoding signature hash for legacy sdk ([#520](https://github.com/opentdf/web-sdk/issues/520)) ([b08158a](https://github.com/opentdf/web-sdk/commit/b08158ae258b8e9bc65cad4b3cf64031de5d8f5b))
* **sdk:** Update ec-wrapped salt value ([#464](https://github.com/opentdf/web-sdk/issues/464)) ([86142ba](https://github.com/opentdf/web-sdk/commit/86142baef4992ebe3e2245435fc97e896a65380a))
* **sdk:** Updates preferred node to 22 ([#408](https://github.com/opentdf/web-sdk/issues/408)) ([a173579](https://github.com/opentdf/web-sdk/commit/a1735793a1129045d4e7db61d99edd5d66b8d911))
* **sdk:** Updates to eslint, and fixes from that ([#423](https://github.com/opentdf/web-sdk/issues/423)) ([fa9271d](https://github.com/opentdf/web-sdk/commit/fa9271d9dc32d6b8c27f6c83c71cb512b8430d99))
* sequential requests instead of promise.all ([#339](https://github.com/opentdf/web-sdk/issues/339)) ([2e81fcb](https://github.com/opentdf/web-sdk/commit/2e81fcb2d75f0d5bfbf0fc683e8dabf0cb3cf00d))
* session.ts Prototype-polluting assignment ([#377](https://github.com/opentdf/web-sdk/issues/377)) ([94993bc](https://github.com/opentdf/web-sdk/commit/94993bc856bdb447d7e4b382ac7449cbce0f5f3d))
* use new policy binding format ([#312](https://github.com/opentdf/web-sdk/issues/312)) ([5e234ee](https://github.com/opentdf/web-sdk/commit/5e234ee0ae013e91b98bf6ca7341377e12565ca4))
