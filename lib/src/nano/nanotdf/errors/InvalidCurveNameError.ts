class InvalidCurveNameError extends Error {
  __proto__: Error;

  constructor() {
    const trueProto = new.target.prototype;
    super('Invalid or unsupported curve name');
    this.__proto__ = trueProto;
    this.name = 'InvalidCurveNameError';
  }
}

export default InvalidCurveNameError;
