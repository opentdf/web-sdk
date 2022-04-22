import { expect } from 'chai';
import { PlaintextStream } from '../../../src/tdf3/client/tdf-stream';
import { isStream } from '../../../src/tdf3/utils';

describe('Utils', () => {
  const stream = new PlaintextStream();

  it('isStream', () => expect(isStream(stream)).to.be.true);
  it('isStream', () =>
    expect(
      isStream({
        pipe: () => {
          // Do nothing
        },
      })
    ).to.be.true);
  it('isStream', () => expect(isStream({})).to.be.false);
});