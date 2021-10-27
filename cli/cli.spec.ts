import { expect } from '@esm-bundle/chai';
import { handleArgs } from './cli.js';

it('parses action parameter', () => {
  expect(handleArgs([])).to.not.have.property('action');
  expect(handleArgs(['--error'])).to.not.have.property('action');
  expect(handleArgs(['--action', 'decrypt'])).to.have.property('action', 'decrypt');
  expect(handleArgs(['--action=encrypt'])).to.have.property('action', 'encrypt');
  expect(handleArgs(['--action", "invalid-command'])).to.not.have.property('action');
});
