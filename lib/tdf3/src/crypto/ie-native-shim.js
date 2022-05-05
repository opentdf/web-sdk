/* globals msCrypto */
/**
 * This class is for IE 10 specifically.  In IE 10 encrypt/decrypt of even small
 * files in pure JS crashes the browser.  So add in a shim specific for IE 10
 * that uses native crypto.
 *
 * @type {*|exports|module.exports}
 */

function cryptoMethod(method) {
  return function cryptoMethodInner(...args) {
    return new Promise((resolve, reject) => {
      const op = msCrypto.subtle[method](...args);
      op.oncomplete = function () {
        resolve(op.result);
      };
      op.onerror = function (err) {
        reject(err);
      };
    });
  };
}

export default {
  encrypt: cryptoMethod('encrypt'),
  decrypt: cryptoMethod('decrypt'),
  importKey: cryptoMethod('importKey'),
};
