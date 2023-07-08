class InvalidCipherError extends Error {
  __proto__: Error;

  constructor() {
    const trueProto = new.target.prototype;
    super('Invalid or unsupported cipher');
    this.__proto__ = trueProto;
    this.name = 'InvalidCipherError';
  }
}

export default InvalidCipherError;
