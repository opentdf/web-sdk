import { assert } from 'chai';
import { sync as rimrafSync } from 'rimraf';
import { mkdirSync, readFileSync } from 'fs';

import { Client as TDF } from '../src';
import { PlaintextStream } from '../src/client/tdf-stream';
import { TDFCiphertextStream } from '../src/client/tdf-cipher-text-stream';
const defaultConfig = {
  organizationName: 'realm',
  clientId: 'id',
  kasEndpoint: 'kas',
  clientSecret: 'secret',
};

const client = new TDF.Client(defaultConfig);

const TEMP_DIR = 'temp/';

describe('client wrapper tests', function () {
  it('client params safe', function () {
    const config = {
      kasEndpoint: 'kasUrl',
      organizationName: 'realm',
      clientId: 'id',
      clientSecret: 'secret',
    };
    new TDF.Client(config);
    assert.deepEqual(config, { ...config });
  });

  it('encrypt params sane', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    assert.ok(!paramsBuilder.getStreamSource());
  });

  it('encrypt params null string source', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    try {
      paramsBuilder.setStringSource(null);
      throw new Error("didn't throw");
    } catch (e) {
      // TODO: type check exception
    }
  });

  it('encrypt params bad string source', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    try {
      paramsBuilder.setStringSource(42);
      throw new Error("didn't throw");
    } catch (e) {
      // TODO: type check exception
    }
  });

  it('encrypt params null file source', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    try {
      paramsBuilder.setFileSource(null);
      throw new Error("didn't throw");
    } catch (e) {
      // TODO: type check exception
    }
  });

  it('encrypt "online" param should be true by default', () => {
    const paramsBuilder = new TDF.EncryptParamsBuilder();

    assert.equal(paramsBuilder.isOnline(), true);
  });

  it('encrypt offline mode can be enabled on setOffline trigger', () => {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    paramsBuilder.setOffline();

    assert.equal(paramsBuilder.isOnline(), false);
  });

  it('encrypt offline mode can be enabled withOffline', () => {
    const paramsBuilder = new TDF.EncryptParamsBuilder().withOffline();

    assert.equal(paramsBuilder.isOnline(), false);
  });

  it('encrypt offline can be toggled', () => {
    const paramsBuilder = new TDF.EncryptParamsBuilder().withOffline().withOnline();
    assert.equal(paramsBuilder.isOnline(), true);
    assert.equal(paramsBuilder.withOffline().isOnline(), false);
    assert.equal(paramsBuilder.withOnline().withOffline().withOffline().isOnline(), false);
    assert.equal(paramsBuilder.withOnline().isOnline(), true);
    assert.equal(paramsBuilder.isOnline(), true);
  });

  it('encrypt params bad file source', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    try {
      paramsBuilder.setFileSource(42);
      throw new Error("didn't throw");
    } catch (e) {
      // TODO: type check exception
    }
  });

  it('encrypt params policy id', function () {
    const params = new TDF.EncryptParamsBuilder()
      .withStringSource('hello world')
      .withPolicyId('foo')
      .build();
    assert.equal('foo', params.getPolicyId());
  });

  it('encrypt params mime type', function () {
    const params = new TDF.EncryptParamsBuilder()
      .withStringSource('hello world')
      .withMimeType('text/plain')
      .build();
    assert.equal(params.mimeType, 'text/plain');
  });

  it('decrypt params sane', function () {
    const paramsBuilder = new TDF.DecryptParamsBuilder();
    assert.ok(!paramsBuilder.getStreamSource());
  });

  it('encrypt error', async function () {
    const encryptParams = new TDF.EncryptParamsBuilder().withStringSource('hello world').build();
    try {
      await client.encrypt(encryptParams);
      assert.fail('did not throw');
    } catch (expected) {
      assert.ok(expected);
    }
  });

  it('decrypt error', async function () {
    const decryptParams = new TDF.DecryptParamsBuilder().withStringSource('not a tdf').build();
    try {
      await client.decrypt(decryptParams);
      assert.fail('did not throw');
    } catch (expected) {
      assert.ok(expected);
    }
  });
});

describe('tdf stream tests', function () {
  before(function () {
    rimrafSync(TEMP_DIR);
    mkdirSync(TEMP_DIR);
  });

  after(function () {
    rimrafSync(TEMP_DIR);
  });
  it('plaintext stream string', async function () {
    const pt = 'hello world';
    const stream = new PlaintextStream();
    stream.push(pt);
    stream.push(null);
    assert.equal(pt, await stream.toString());
  });
  it('plaintext stream buffer', async function () {
    const pt = 'hello world';
    const stream = new PlaintextStream();
    stream.push(pt);
    stream.push(null);
    assert.equal(pt, (await stream.toBuffer()).toString('utf-8'));
  });
  it('plaintext stream file', async function () {
    const pt = 'hello world';
    const filename = `${TEMP_DIR}/plain.txt`;
    const stream = new PlaintextStream();
    stream.push(pt);
    stream.push(null);
    await stream.toFile(filename);
    const rt = readFileSync(filename, { encoding: 'utf-8' });
    assert.equal(pt, rt);
  });
  it('plaintext stream window size', async function () {
    const stream = new PlaintextStream(2);
    assert.ok(stream.write('a'));
    assert.notOk(stream.write('a'));
  });
  it('tdf stream string', async function () {
    const pt = 'hello world';
    const stream = new TDFCiphertextStream();
    stream.push(pt);
    stream.push(null);
    assert.equal(pt, await stream.toString());
  });
  it('tdf stream buffer', async function () {
    const pt = 'hello world';
    const stream = new TDFCiphertextStream();
    stream.push(pt);
    stream.push(null);
    assert.equal(pt, (await stream.toBuffer()).toString('utf-8'));
  });
  it('tdf stream file', async function () {
    const pt = 'hello world';
    const filename = `${TEMP_DIR}/plain.tdf`;
    const stream = new TDFCiphertextStream();
    stream.push(pt);
    stream.push(null);
    await stream.toFile(filename);
    const rt = readFileSync(filename, { encoding: 'utf-8' }); // decode as utf 8
    assert.equal(pt, rt);
  });
  it('tdf stream window size', async function () {
    const stream = new TDFCiphertextStream(2);
    assert.ok(stream.write('a'));
    assert.notOk(stream.write('a'));
  });
});
