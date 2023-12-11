import { decrypt } from '../../../tdf3/src/crypto/decrypt-worker';
import sinon from 'sinon';

const WorkerImplementation = globalThis.Worker;

describe('', () => {
  beforeAll(() => {
    globalThis.Worker = class Worker {
      private spy: sinon.SinonSpy;
      postMessage(data) {
          this.spy = sinon.spy();
          this.spy(data);
          return this.onmessage(data)
      }
      onmessage(data) {}
    };
  })
  it('', async () => {

  });
  afterAll(() => {
    globalThis.Worker = WorkerImplementation;
  })
});

