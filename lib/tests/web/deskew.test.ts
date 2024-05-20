import { expect } from '@esm-bundle/chai';
import axios from 'axios';
import sinon from 'sinon';
import {
  estimateSkew,
  estimateSkewFromHeaders,
} from '../../src/deskew.js';

function mockApiResponse(date = '', status = 200) {
  return new globalThis.Response(`{}`, {
    status,
    headers: { 'Content-type': 'application/json', Date: date },
  });
}

describe('skew estimation', () => {
  function initSandbox(local: number, remote: string) {
    const sandbox = sinon.createSandbox();
    const nowAndThen = sandbox.stub(Date, 'now');
    nowAndThen.returns(local);
    const fetchLives = sandbox.stub(globalThis, 'fetch');
    fetchLives.callsFake(async (resource, init) => {
      if (resource === 'http://localhost') {
        return mockApiResponse(remote);
      }
      console.log(`trying to fetch( resource: [${resource}], init:`, init);
      return mockApiResponse('Thu, 1 Jan 1970 00:00:01 GMT', 404);
    });
    return sandbox;
  }

  describe('estimateSkew', () => {
    it('fetch', async () => {
      const estimate = await estimateSkew();
      expect(estimate).to.be.lessThan(2);
      expect(estimate).to.be.greaterThan(-2);
    });
    it('big drift', async () => {
      const sandbox = initSandbox(501 * 1000, 'Thu, 1 Jan 1970 00:00:00 GMT');
      try {
        const estimate = await estimateSkew();
        expect(estimate).to.eql(-500);
      } finally {
        sandbox.restore();
      }
    });
  });

  describe('estimateSkewFromHeaders', () => {
    it('axios', async () => {
      console.log(window.origin);
      const before = Date.now();
      const aResponse = await axios.get(window.origin);
      await new Promise((r) => setTimeout(r, 1000));
      const estimate = estimateSkewFromHeaders(aResponse.headers, before);
      expect(estimate).to.be.lessThan(3);
      expect(estimate).to.be.greaterThan(-3);
    });
  });
});
