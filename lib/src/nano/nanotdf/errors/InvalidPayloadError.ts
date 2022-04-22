class InvalidPayloadError extends Error {
  __proto__: Error;

  constructor(inRange: boolean) {
    const trueProto = new.target.prototype;
    if (inRange) {
      super('Invalid Payload Length');
    } else {
      super('Payload Length Out Of Range');
    }
    this.__proto__ = trueProto;
    this.name = 'InvalidPayloadError';
  }
}

export default InvalidPayloadError;
