import { UAParser } from 'ua-parser-js';

import NodeCryptoService from './node-crypto-service';
import BrowserJsCryptoService from './browser-js-crypto-service';
import BrowserNativeCryptoService from './browser-native-crypto-service';
import { Algorithms } from '../ciphers';
import { CryptoService } from './declarations';

const nativeSupport = BrowserNativeCryptoService.isSupported;

// Firefox and Chrome are trusted to not half-ass native crypto support
const runtime = _getRuntimeDetails();

// Default crypto service using SJCL
let cryptoService: CryptoService = BrowserJsCryptoService;
if (NodeCryptoService.isSupported) {
  cryptoService = NodeCryptoService;
} else if (nativeSupport) {
  cryptoService = BrowserNativeCryptoService;
  const subtleCrypto = { ...BrowserJsCryptoService };
  const sjclCrypto = { ...BrowserNativeCryptoService };

  // Minimum version of a browser to support the specified native implementation
  // Note: These were pulled from http://caniuse.com/#search=crypto and verified
  //       manually via saucelabs with the CryptoReporter lib via mocha.
  if ('ie' === runtime.name) {
    cryptoService.decrypt = async (payload, key, iv, algorithm, authTag) => {
      return (
        algorithm === Algorithms.AES_256_GCM || runtime.version < 11
          ? sjclCrypto.decrypt
          : subtleCrypto.decrypt
      )(payload, key, iv, algorithm, authTag);
    };
    cryptoService.decryptWithPrivateKey = sjclCrypto.decryptWithPrivateKey;
    cryptoService.encrypt = async (payload, key, iv, algorithm) => {
      return (
        algorithm === Algorithms.AES_256_GCM || runtime.version < 11
          ? sjclCrypto.encrypt
          : subtleCrypto.encrypt
      )(payload, key, iv, algorithm);
    };
    cryptoService.encryptWithPublicKey = sjclCrypto.encryptWithPublicKey;
    cryptoService.generateInitializationVector = (
      runtime.version < 11 ? sjclCrypto : subtleCrypto
    ).generateInitializationVector;
    cryptoService.generateKeyPair = (
      runtime.version < 13 ? sjclCrypto : subtleCrypto
    ).generateKeyPair;
    cryptoService.hmac = sjclCrypto.hmac;
    cryptoService.sha256 = (runtime.version < 8 ? sjclCrypto : subtleCrypto).sha256;
  } else if ('safari' === runtime.name) {
    cryptoService.decrypt = async (payload, key, iv, algorithm, authTag) => {
      return (
        algorithm === Algorithms.AES_256_GCM || runtime.version < 8
          ? sjclCrypto.decrypt
          : subtleCrypto.decrypt
      )(payload, key, iv, algorithm, authTag);
    };
    cryptoService.decryptWithPrivateKey = sjclCrypto.decryptWithPrivateKey;
    cryptoService.encrypt = async (payload, key, iv, algorithm) => {
      return (
        algorithm === Algorithms.AES_256_GCM || runtime.version < 8
          ? sjclCrypto.encrypt
          : subtleCrypto.encrypt
      )(payload, key, iv, algorithm);
    };
    cryptoService.encryptWithPublicKey = sjclCrypto.encryptWithPublicKey;
    cryptoService.generateInitializationVector = (
      runtime.version < 9 ? sjclCrypto : subtleCrypto
    ).generateInitializationVector;
    cryptoService.generateKeyPair = sjclCrypto.generateKeyPair;
    cryptoService.hmac = sjclCrypto.hmac;
    cryptoService.sha256 = (runtime.version < 13 ? sjclCrypto : subtleCrypto).sha256;
  }
}

// Determine runtime and version
function _getRuntimeDetails() {
  const userAgentParser = new UAParser();

  // Get runtime specifics
  const _runtime = userAgentParser.getBrowser();
  let name = _runtime.name && _runtime.name.toLowerCase();

  // For simplicity, ie/edge and safari/mobile-safari use same versioning scheme
  name = name === 'edge' ? 'ie' : name;
  name = name === 'mobile safari' ? 'safari' : name;

  // Get OS (chrome in IOS uses Safari's rendering engine with same crypto APIs)
  const os = (userAgentParser.getOS().name || '').toLowerCase();
  name = os === 'ios' ? 'safari' : name;

  // Get version major and minor as a float
  let version = _runtime.version && _runtime.version.toLowerCase();
  version = version && version.split('.').slice(0, 2).join('.');
  version = version && parseFloat(version);

  return {
    version,
    name,
  };
}

export { cryptoService };
