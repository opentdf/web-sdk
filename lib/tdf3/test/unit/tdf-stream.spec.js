import { assert } from 'chai';
import { restore, stub, replace } from 'sinon';
import { readFileSync } from 'fs';

import * as utils from '../../src/utils';
import * as chunkers from '../../src/utils/chunkers';
import { PlaintextStream } from '../../src/client/tdf-stream';

describe('tdf-stream browser test', () => {
  beforeEach(() => {
    stub(utils, 'inBrowser').callsFake(() => true);
  });

  afterEach(() => {
    restore();
  });

  it('Should call _saveFile with jpg mime type when jpg filed passed', () => {
    // stream to buffer stubed to return sample test file buffer;
    replace(chunkers, 'streamToBuffer', () =>
      readFileSync('./test/__fixtures__/mimeCheckFixtures/sample.jpg')
    );

    const stream = new PlaintextStream();
    stub(stream, '_saveFile').callsFake((filedata, { mime }) => {
      assert.strictEqual(mime, 'image/jpeg');
    });

    stream.toFile();
  });

  it('Should call _saveFile with zip mime type', () => {
    // stream to buffer stubed to return sample test file buffer;
    replace(chunkers, 'streamToBuffer', () =>
      readFileSync('./test/__fixtures__/mimeCheckFixtures/sample.jpg.zip')
    );

    const stream = new PlaintextStream();
    stub(stream, '_saveFile').callsFake((filedata, { mime }) => {
      assert.strictEqual(mime, 'application/zip');
    });

    stream.toFile();
  });

  it('Should call _saveFile with octet-stream mime type and filename if tdf passed', () => {
    // tdf is not a mime type (real mime type is zip). We need put file name
    // with tdf extension if file name wasnt passed
    replace(chunkers, 'streamToBuffer', () =>
      readFileSync('./test/__fixtures__/mimeCheckFixtures/sample.tdf')
    );

    const stream = new PlaintextStream();
    stub(stream, '_saveFile').callsFake((filedata, { mime }, filename) => {
      assert.strictEqual(mime, 'application/octet-stream');
      assert.strictEqual(filename, 'download.tdf');
    });

    stream.toFile();
  });
});
