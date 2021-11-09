class InvalidEphemeralKeyError extends Error {
  __proto__: Error;

  constructor() {
    const trueProto = new.target.prototype;
    super('Incorrect length for ephemeral key');
    this.__proto__ = trueProto;
    this.name = 'InvalidEphemeralKeyError';
  }
}

export default InvalidEphemeralKeyError;
