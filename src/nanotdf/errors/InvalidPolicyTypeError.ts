class InvalidPolicyTypeError extends Error {
  __proto__: Error;

  constructor() {
    const trueProto = new.target.prototype;
    super('Invalid or unsupported policy type');
    this.__proto__ = trueProto;
    this.name = 'InvalidPolicyTypeError';
  }
}

export default InvalidPolicyTypeError;
