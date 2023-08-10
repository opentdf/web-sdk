import { expect } from '@esm-bundle/chai';
import axios from 'axios';
import sinon from 'sinon';
import {
  estimateSkew,
  estimateSkewFromHeaders,
  padSlashToUrl,
  rstrip,
  safeUrlCheck,
  validateSecureUrl,
} from '../../src/utils.js';

describe('rstrip', () => {
  describe('default', () => {
    it('undefined', () => {
      // @ts-expect-error rstrip requires parameters
      expect(rstrip()).to.be.undefined;
    });
    it('empty', () => {
      expect(rstrip('')).to.eql('');
    });
    it('blank', () => {
      expect(rstrip('    ')).to.eql('');
    });
    it('leftovers', () => {
      expect(rstrip('hey    ')).to.eql('hey');
    });
    it('leftovers with stuff in front', () => {
      expect(rstrip('  hey    ')).to.eql('  hey');
    });
  });
  describe('characters', () => {
    it('empty', () => {
      expect(rstrip('', '/')).to.eql('');
    });
    it('samesey', () => {
      expect(rstrip('/', '/')).to.eql('');
    });
    it('samesies', () => {
      expect(rstrip('//', '/')).to.eql('');
      expect(rstrip('///////', '/')).to.eql('');
      expect(rstrip('//////////', '/')).to.eql('');
    });
    it('leftovers', () => {
      expect(rstrip('hey  //', '/')).to.eql('hey  ');
    });
    it('leftovers with stuff in front', () => {
      expect(rstrip('///hey.you', '/')).to.eql('///hey.you');
      expect(rstrip('https://hey.you', '/')).to.eql('https://hey.you');
      expect(rstrip('https://hey.you/', '/')).to.eql('https://hey.you');
      expect(rstrip('https://hey.you//', '/')).to.eql('https://hey.you');
    });
  });
});

describe('validateSecureUrl', () => {
  it('https is preferred', () => {
    expect(validateSecureUrl('https://my.xyz/somewhere')).to.be.true;
    expect(validateSecureUrl('https://my.home')).to.be.true;
    expect(validateSecureUrl('https://my.home:65432/')).to.be.true;
    expect(validateSecureUrl('https://my.home:65432')).to.be.true;
    expect(validateSecureUrl('http://my.home')).to.be.false;
    expect(validateSecureUrl('http://my.home/')).to.be.false;
    expect(validateSecureUrl('http://my.home:65432/')).to.be.false;
    expect(validateSecureUrl('http://my.home:65432')).to.be.false;
  });
  it('allows locals', () => {
    expect(validateSecureUrl('http://localhost/somewhere')).to.be.true;
    expect(validateSecureUrl('http://127.0.0.1')).to.be.true;
    expect(validateSecureUrl('http://127.0.0.1.com')).to.be.false;
    expect(validateSecureUrl('http://127.0-0.1')).to.be.false;
    expect(validateSecureUrl('http://localhost:12312/somewhere')).to.be.true;
    expect(validateSecureUrl('http://localhost.com/somewhere')).to.be.false;
  });
  it('allows internals', () => {
    expect(validateSecureUrl('http://docker.internal/somewhere')).to.be.true;
    expect(validateSecureUrl('http://svc.cluster.local')).to.be.true;
    expect(validateSecureUrl('http://amz.svc.cluster.local')).to.be.true;
    expect(validateSecureUrl('http://somesvc.cluster.local')).to.be.false;
  });
  it('mangled urls', () => {
    expect(validateSecureUrl('///hey.you')).to.be.false;
    expect(validateSecureUrl('')).to.be.false;
    expect(validateSecureUrl('https')).to.be.false;
  });
});

describe('padSlashToUrl', () => {
  it('slashadds', () => {
    expect(padSlashToUrl('https://my.xyz')).to.equal('https://my.xyz/');
    expect(padSlashToUrl('https://my.xyz/')).to.equal('https://my.xyz/');
    expect(padSlashToUrl('https://my.xyz/somewhere')).to.equal('https://my.xyz/somewhere/');
    expect(padSlashToUrl('https://my.xyz/somewhere/')).to.equal('https://my.xyz/somewhere/');
  });
});

describe('safeUrlCheck', () => {
  it('some checks', () => {
    expect(() => safeUrlCheck([], 'https://my.xyz/somewhere/else')).to.throw('Invalid request URL');
    expect(() => safeUrlCheck([''], 'https://my.xyz/somewhere/else')).to.throw(
      'Invalid request URL'
    );
    expect(() => safeUrlCheck(['https://my.xyz'], 'https://my.xyz/somewhere')).to.not.throw(
      'Invalid request URL'
    );
    expect(() => safeUrlCheck(['https://my.xyz'], 'https://my.xyz.com/somewhere/else')).to.throw(
      'Invalid request URL'
    );
    expect(() => safeUrlCheck(['https://my.xyz'], 'http://my.xyz/somewhere/else')).to.throw(
      'Invalid request URL'
    );
    expect(() =>
      safeUrlCheck(['https://my.xyz/somewhere'], 'https://my.xyz/somewhere/else')
    ).to.not.throw('Invalid request URL');
    expect(() =>
      safeUrlCheck(
        ['https://your.place', 'https://my.xyz/somewhere'],
        'https://my.xyz/somewhere/else'
      )
    ).to.not.throw('Invalid request URL');
    expect(() =>
      safeUrlCheck(['https://my.xyz/somewhere'], 'https://my.xyz/somewhereelse/')
    ).to.throw('Invalid request URL');
    expect(() => safeUrlCheck(['https://my.xyz/somewhere'], 'https://my.xyz/elsewhere/')).to.throw(
      'Invalid request URL'
    );
  });
});

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
      expect(estimate).to.be.lessThan(2);
      expect(estimate).to.be.greaterThan(-2);
    });
  });
});
