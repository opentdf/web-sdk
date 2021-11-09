class SignatureError extends Error {
  __proto__: Error;

  constructor(shouldHaveSignature: boolean) {
    const trueProto = new.target.prototype;
    if (shouldHaveSignature) {
      super('Could not find signature');
    } else {
      super("Found signature when there shouldn't be one");
    }
    this.__proto__ = trueProto;
    this.name = 'SignatureError';
  }
}

export default SignatureError;
