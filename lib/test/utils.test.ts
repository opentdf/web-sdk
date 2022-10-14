import { expect } from '@esm-bundle/chai';
import { rstrip } from '../src/utils.js';

describe('rstrip', () => {
  describe('default', () => {
    it('undefined', () => {
      // @ts-ignore
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
