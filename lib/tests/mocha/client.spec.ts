import { assert } from 'chai';
import { Client as TDF } from '../../tdf3/src/index.js';
import { DecoratedReadableStream } from '../../tdf3/src/client/DecoratedReadableStream.js';

describe('client wrapper tests', function () {
  it('client params safe from updating', function () {
    const config = {
      kasEndpoint: 'kasUrl',
      clientId: 'id',
    };
    const client = new TDF.Client(config);
    assert.deepEqual(config, { ...config });
    assert.deepEqual(config.kasEndpoint, client.kasEndpoint);

    config.kasEndpoint = 'kas2';
    assert.notDeepEqual(config.kasEndpoint, client.kasEndpoint);
  });

  it('encrypt params sane', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    assert.ok(!paramsBuilder.getStreamSource());
  });

  it('encrypt params null string source', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    try {
      // @ts-ignore
      paramsBuilder.setStringSource(null);
      throw new Error("didn't throw");
    } catch (e) {
      // TODO: type check exception
    }
  });

  it('encrypt params bad string source', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    try {
      // @ts-ignore
      paramsBuilder.setStringSource(42);
      throw new Error("didn't throw");
    } catch (e) {
      // TODO: type check exception
    }
  });

  it('encrypt params null file source', function () {
    const paramsBuilder = new TDF.DecryptParamsBuilder();
    try {
      // @ts-ignore
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
    const paramsBuilder = new TDF.DecryptParamsBuilder();
    try {
      // @ts-ignore
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
    // @ts-ignore
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
    const config = {
      kasEndpoint: 'kasUrl',
      clientId: 'id',
    };
    const client = new TDF.Client(config);
    try {
      await client.encrypt(encryptParams);
      assert.fail('did not throw');
    } catch (expected) {
      assert.ok(expected);
    }
  });

  it('decrypt error', async function () {
    const decryptParams = new TDF.DecryptParamsBuilder().withStringSource('not a tdf').build();
    const config = {
      kasEndpoint: 'kasUrl',
      clientId: 'id',
    };
    const client = new TDF.Client(config);
    try {
      await client.decrypt(decryptParams);
      assert.fail('did not throw');
    } catch (expected) {
      assert.ok(expected);
    }
  });
});

describe('tdf stream tests', function () {
  it('plaintext stream string', async function () {
    const pt = new TextEncoder().encode('hello world');
    const stream = new DecoratedReadableStream({
      start(controller) {
        controller.enqueue(pt);
        controller.close();
      },
    });
    assert.equal('hello world', await stream.toString());
  });
  it('plaintext stream buffer', async function () {
    const pt = new TextEncoder().encode('hello world');
    const stream = new DecoratedReadableStream({
      start(controller) {
        controller.enqueue(pt);
        controller.close();
      },
    });
    assert.equal('hello world', new TextDecoder().decode(await stream.toBuffer()));
  });
});
