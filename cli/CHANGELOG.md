# Changelog

## [0.4.0](https://github.com/opentdf/web-sdk/compare/cli-v0.3.3...cli-v0.4.0) (2025-06-19)


### Features

* Assertion signing key handling and verification in the CLI ([#409](https://github.com/opentdf/web-sdk/issues/409)) ([242150b](https://github.com/opentdf/web-sdk/commit/242150b69d2fd428ed4c6cab4d27b1d258ebe11a))
* **cli:** Adds --allowList parameter to cli ([#328](https://github.com/opentdf/web-sdk/issues/328)) ([297cec6](https://github.com/opentdf/web-sdk/commit/297cec667ef3e87263ab9e58fae1482750009156))
* **cli:** Adds `--policyBinding ecdsa` option ([#352](https://github.com/opentdf/web-sdk/issues/352)) ([4e54c0d](https://github.com/opentdf/web-sdk/commit/4e54c0d6d9cd6b6d1c05296cf954431970509367))
* **cli:** Enables experimental ec in KAOs ([#457](https://github.com/opentdf/web-sdk/issues/457)) ([203563c](https://github.com/opentdf/web-sdk/commit/203563ce800f13bcf2efded7e499efae46debb99))
* **cli:** Pass the platform url on decrypt, add the platform kas to the allowlist when fetching ([#565](https://github.com/opentdf/web-sdk/issues/565)) ([5afd0d0](https://github.com/opentdf/web-sdk/commit/5afd0d058f9111a8fef420ec560e0dcf4fde6007))
* **core:** KID in NanoTDF ([#325](https://github.com/opentdf/web-sdk/issues/325)) ([6d01eff](https://github.com/opentdf/web-sdk/commit/6d01eff5bdf2f9fde688b3dab4e57470fb255c88))
* export connect rpc generated platform from package.json ([#610](https://github.com/opentdf/web-sdk/issues/610)) ([cbd8a10](https://github.com/opentdf/web-sdk/commit/cbd8a10eb5e277c40b04e894f62bb3f53aa2a483))
* **lib:** Bump for EC feature ([#452](https://github.com/opentdf/web-sdk/issues/452)) ([6178877](https://github.com/opentdf/web-sdk/commit/6178877c8a307fe461f3ce348cb63a7204ccda45))
* **lib:** Load abac config from policy service ([#351](https://github.com/opentdf/web-sdk/issues/351)) ([48b2442](https://github.com/opentdf/web-sdk/commit/48b24426c26ff56e0edb7d2e78eda34e844be135))
* **lib:** Updated error types ([#362](https://github.com/opentdf/web-sdk/issues/362)) ([7fb29c5](https://github.com/opentdf/web-sdk/commit/7fb29c5ef519720f7d2c9c8e488e6246743e8d1c))
* **sdk:** Adds OpenTDF.open method ([#485](https://github.com/opentdf/web-sdk/issues/485)) ([6ba9044](https://github.com/opentdf/web-sdk/commit/6ba90445b263bf8084b421faab742c93688446dd))
* **sdk:** Allow custom KAO array templates ([#307](https://github.com/opentdf/web-sdk/issues/307)) ([fd1b386](https://github.com/opentdf/web-sdk/commit/fd1b38677b309083a54c0818b316d9e39d7aa649))
* **sdk:** Allows skipping verification ([#371](https://github.com/opentdf/web-sdk/issues/371)) ([8529461](https://github.com/opentdf/web-sdk/commit/85294612fb6886fa4da6cf4d070c54168ed634de))
* **sdk:** connect rpc client export ([#545](https://github.com/opentdf/web-sdk/issues/545)) ([92de145](https://github.com/opentdf/web-sdk/commit/92de1451cc18c9385d35331dafa4b078e7a1736b))
* **sdk:** ec-wrapped key support ([#422](https://github.com/opentdf/web-sdk/issues/422)) ([9d4eab4](https://github.com/opentdf/web-sdk/commit/9d4eab46de11bbbe8bc660149fad245853d18e94))
* **sdk:** get KASes list from platform when allowedKases list is not passed ([#557](https://github.com/opentdf/web-sdk/issues/557)) ([598c39f](https://github.com/opentdf/web-sdk/commit/598c39f2bccb4eb2a0f19143cf1d47d07bd65232))
* **sdk:** remove hex encoding for segment hash ([#397](https://github.com/opentdf/web-sdk/issues/397)) ([ec4a55a](https://github.com/opentdf/web-sdk/commit/ec4a55a2890375b7dd5be61dafa93b505e54be7b))
* **sdk:** sdk to use connect rpc calls ([#596](https://github.com/opentdf/web-sdk/issues/596)) ([f8e54e5](https://github.com/opentdf/web-sdk/commit/f8e54e5ff0a5775a2e7c3e487d1f16b227231583))
* **sdk:** Updates to jose 6.x ([#449](https://github.com/opentdf/web-sdk/issues/449)) ([9667747](https://github.com/opentdf/web-sdk/commit/966774769a674d65b5a32e002687f08104844732))


### Bug Fixes

* add ignoreAllowList flag ([#331](https://github.com/opentdf/web-sdk/issues/331)) ([29a9b82](https://github.com/opentdf/web-sdk/commit/29a9b82e98bd99c95a59288949ff182103c09a05))
* Assertion verification key input ([#412](https://github.com/opentdf/web-sdk/issues/412)) ([5be9bb1](https://github.com/opentdf/web-sdk/commit/5be9bb11bb73b5859ea7f18a6309dd70e93dc94a))
* **cli:** Better errors and properly set exit code in more cases ([#418](https://github.com/opentdf/web-sdk/issues/418)) ([11ad526](https://github.com/opentdf/web-sdk/commit/11ad526ed29f8c334d1d048dacd8302795ce5589))
* **cli:** Enables concurrent rewrap in cli ([#391](https://github.com/opentdf/web-sdk/issues/391)) ([ab40664](https://github.com/opentdf/web-sdk/commit/ab40664e5b0fb26b9056066fdb6fa2224ffd74a5))
* **client:** Normalize allowlist to origins ([#321](https://github.com/opentdf/web-sdk/issues/321)) ([ac1f634](https://github.com/opentdf/web-sdk/commit/ac1f634df2db559f895ac1317dad8c5af14da680))
* **core:** npm audit fix ([#380](https://github.com/opentdf/web-sdk/issues/380)) ([496f07c](https://github.com/opentdf/web-sdk/commit/496f07ca7029ded39bd0c71a59f1c7220dd419c1))
* keySplitInfo Promise.any Promise.all ([#379](https://github.com/opentdf/web-sdk/issues/379)) ([c6cdbef](https://github.com/opentdf/web-sdk/commit/c6cdbefc5c2cffda0c8a70972ee115e60112bfa4))
* **sdk:** Bump version no. to 0.3.2 ([#536](https://github.com/opentdf/web-sdk/issues/536)) ([5924bc9](https://github.com/opentdf/web-sdk/commit/5924bc9f3cdb694b8f1be8ddd53f1b59e4f96115))
* **sdk:** Fixes generating ztdf 4.2.2 output ([#530](https://github.com/opentdf/web-sdk/issues/530)) ([ab42e5a](https://github.com/opentdf/web-sdk/commit/ab42e5a1f8463d6cbc18695f53c56b3403950fdd))
* **sdk:** Lets new API set nano binding type ([#455](https://github.com/opentdf/web-sdk/issues/455)) ([26879ef](https://github.com/opentdf/web-sdk/commit/26879ef9e81dbe5b8daff065c2ad7ef433072669))
* **sdk:** npm audit fix ([#410](https://github.com/opentdf/web-sdk/issues/410)) ([840fd29](https://github.com/opentdf/web-sdk/commit/840fd297a419d5fa402e68bed04b45698d2d5214))
* **sdk:** Sets schemaVersion, not tdf_spec_version ([#414](https://github.com/opentdf/web-sdk/issues/414)) ([74d326b](https://github.com/opentdf/web-sdk/commit/74d326b940049e9e9943648cd71ade723d16522d))
* **sdk:** support hex encoding signature hash for legacy sdk ([#520](https://github.com/opentdf/web-sdk/issues/520)) ([b08158a](https://github.com/opentdf/web-sdk/commit/b08158ae258b8e9bc65cad4b3cf64031de5d8f5b))
* **sdk:** Updates preferred node to 22 ([#408](https://github.com/opentdf/web-sdk/issues/408)) ([a173579](https://github.com/opentdf/web-sdk/commit/a1735793a1129045d4e7db61d99edd5d66b8d911))
* **sdk:** Updates to eslint, and fixes from that ([#423](https://github.com/opentdf/web-sdk/issues/423)) ([fa9271d](https://github.com/opentdf/web-sdk/commit/fa9271d9dc32d6b8c27f6c83c71cb512b8430d99))
