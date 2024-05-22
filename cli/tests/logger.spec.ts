import { expect } from '@esm-bundle/chai';
import { createSandbox, SinonStub as Stub } from 'sinon';
import { log } from '../src/logger.js';

describe('privateFunction()', function () {
  const sandbox = createSandbox();
  beforeEach(() => {
    sandbox.stub(console, 'log');
    sandbox.stub(console, 'info');
    sandbox.stub(console, 'warn');
    sandbox.stub(console, 'error');
  });
  afterEach(() => {
    sandbox.restore();
  });

  it('level check low', () => {
    log.level = 'SILLY';
    log('SILLY', 'what');
    const L = <Stub>console.log;
    expect(L.lastCall.args).to.eql(['[SILLY] what']);
  });

  it('level check high', () => {
    log.level = 'WARNING';
    log('ERROR', 'what');
    log('SILLY', 'now');
    const E = <Stub>console.error;
    expect(E.lastCall.args).to.eql(['[ERROR] what']);
    const L = <Stub>console.log;
    expect(L.calledOnce).to.be.false;
  });
});
