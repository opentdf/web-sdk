class InvalidDataTypeError extends Error {
  __proto__: Error;

  constructor() {
    const trueProto = new.target.prototype;
    super(`Invalid datatype, expecting a string or ArrayBuffer`);
    this.__proto__ = trueProto;
    this.name = 'InvalidDataTypeError';
  }
}

export default InvalidDataTypeError;
