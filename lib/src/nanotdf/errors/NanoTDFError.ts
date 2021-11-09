class NanoTDFError extends Error {
  __proto__: Error;
  err?: Error;

  constructor(msg: string, err?: Error) {
    const trueProto = new.target.prototype;
    super(msg);
    this.__proto__ = trueProto;
    this.err = err;
  }

  get stack(): string | undefined {
    return this.err ? `${this.stack}\nCaused by: ${this.err?.stack}` : this.stack;
  }
}

export default NanoTDFError;
