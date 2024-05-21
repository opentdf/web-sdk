import { expect } from '@esm-bundle/chai';
import { padSlashToUrl, rstrip, safeUrlCheck, validateSecureUrl } from '../../src/urltils.js';

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

  it('returns invalid url', () => {
    try {
      safeUrlCheck([], 'https://my.xyz/somewhere/else');
      expect.fail();
    } catch (e) {
      expect(e).to.have.property('url', 'https://my.xyz/somewhere/else');
    }
  });
});
