import { supportedCiphers } from '../ciphers.ts';

export default class UnsupportedCipherError extends Error {
  __proto__: Error;

  constructor() {
    const trueProto = new.target.prototype;
    super(`Unsupported cipher [${supportedCiphers}]`);
    this.__proto__ = trueProto;
  }
}
