import { expect } from 'chai';
import { escHtml, escJavaScript } from '../../../src/templates';

describe('Validate html escaping', () => {
  it('esc no op', () => {
    expect(escHtml('')).to.equal('');
  });

  it('some actual escaping', () => {
    expect(escHtml(`What'"' do you &amp; <say>`)).to.equal(
      'What&#39;&#34;&#39; do you &#38;amp; &#60;say>'
    );
  });
});
describe('Validate javascript escaping', () => {
  it('escJavaScript no op', () => {
    expect(escJavaScript('')).to.equal('');
  });

  it('some actual escaping', () => {
    expect(escJavaScript(`What'"' do you &amp; <say>`)).to.equal(
      "What\\'\\\"\\' do you &amp; \\074say>"
    );
  });
});
