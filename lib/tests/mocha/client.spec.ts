import { assert, expect } from 'chai';
import sinon from 'sinon';
import { Client as TDF } from '../../tdf3/src/index.js';
import { DecoratedReadableStream } from '../../tdf3/src/client/DecoratedReadableStream.js';
import { findEntryInCache } from '../../tdf3/src/client/index.js';
import { getMocks } from '../mocks/index.js';
import { Algorithm, Value } from '../../src/platform/policy/objects_pb.js';
import { create } from '@bufbuild/protobuf';
import { GetAttributeValuesByFqnsResponseSchema } from '../../src/platform/policy/attributes/attributes_pb.js';
import { base64 } from '../../src/encodings/index.js';
import { Attribute } from 'src/policy/attributes.js';

describe('client wrapper tests', function () {
  it('client params safe from updating', function () {
    const config = {
      kasEndpoint: 'https://kasUrl',
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
    expect(() => {
      // @ts-ignore
      paramsBuilder.setStringSource(null);
    }).to.throw();
  });

  it('encrypt params bad string source', function () {
    const paramsBuilder = new TDF.EncryptParamsBuilder();
    expect(() => {
      // @ts-ignore
      paramsBuilder.setStringSource(42);
    }).to.throw();
  });

  it('encrypt params null file source', function () {
    const paramsBuilder = new TDF.DecryptParamsBuilder();
    expect(() => {
      // @ts-ignore
      paramsBuilder.setFileSource(null);
    }).to.throw();
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
    expect(() => {
      // @ts-ignore
      paramsBuilder.setFileSource(42);
    }).to.throw();
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
      kasEndpoint: 'https://kasUrl',
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
      kasEndpoint: 'https://kasUrl',
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

  it('encrypt autoconfigure hydrates fqns via getAttributeValuesByFqns', async function () {
    const Mocks = getMocks();
    const authProvider = {
      updateClientPublicKey: async () => {},
      withCreds: async (httpReq: TDF.HttpRequest) => ({
        ...httpReq,
        headers: { ...httpReq.headers, Authorization: 'Bearer dummy-auth-token' },
      }),
    };

    const kasValueUri = 'https://kas.value.example/kas';
    const kasAttributeUri = 'https://kas.attribute.example/kas';

    const attributeValueFqn = 'http://example.com/attr/value-keys/value/one';
    const attributeOnlyFqn = 'http://example.com/attr/attr-keys/value/two';

    const valueWithAttribute: Value = {
      $typeName: 'policy.Value',
      fqn: attributeValueFqn,
      kasKeys: [
        {
          $typeName: 'policy.SimpleKasKey',
          kasId: 'kas-value-1',
          kasUri: kasValueUri,
          publicKey: {
            $typeName: 'policy.SimpleKasPublicKey',
            pem: Mocks.kasPublicKey,
            kid: 'value-kid-1',
            algorithm: Algorithm.RSA_2048,
          },
        },
      ],
      id: 'value-id-1',
      attribute: {
        $typeName: 'policy.Attribute',
        id: 'attr-id-value',
        name: 'value-keys',
        fqn: 'http://example.com/attr/value-keys',
        rule: 0,
        values: [],
        grants: [],
        kasKeys: [],
        namespace: {
          $typeName: 'policy.Namespace',
          id: 'ns-id-value',
          name: 'example.com',
          fqn: 'http://example.com',
          grants: [],
          kasKeys: [],
          rootCerts: [],
        },
      },
      value: 'one',
      grants: [],
      active: true,
      subjectMappings: [],
      resourceMappings: [],
      obligations: [],
    };

    const attributeOnly: Attribute = {
      $typeName: 'policy.Attribute',
      id: 'attr-id-attr',
      name: 'attr-keys',
      fqn: 'http://example.com/attr/attr-keys',
      rule: 0,
      values: [],
      grants: [],
      kasKeys: [
        {
          $typeName: 'policy.SimpleKasKey',
          kasId: 'kas-attr-1',
          kasUri: kasAttributeUri,
          publicKey: {
            $typeName: 'policy.SimpleKasPublicKey',
            pem: Mocks.kasPublicKey,
            kid: 'attr-kid-1',
            algorithm: Algorithm.RSA_2048,
          },
        },
      ],
      namespace: {
        $typeName: 'policy.Namespace',
        id: 'ns-id-attr',
        name: 'example.com',
        fqn: 'http://example.com',
        grants: [],
        kasKeys: [],
        rootCerts: [],
      },
    };

    const getAttributeValuesByFqnsResponse = create(GetAttributeValuesByFqnsResponseSchema, {
      fqnAttributeValues: {
        [attributeValueFqn]: {
          value: valueWithAttribute,
          attribute: valueWithAttribute.attribute,
        },
        [attributeOnlyFqn]: {
          attribute: attributeOnly,
        },
      },
    });

    const fetchStub = sinon.stub(globalThis, 'fetch').callsFake(async (input) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('GetAttributeValuesByFqns')) {
        return new Response(JSON.stringify(getAttributeValuesByFqnsResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const client = new TDF.Client({
      kasEndpoint: 'https://kas.default.example/kas',
      clientId: 'id',
      dpopKeys: Mocks.entityKeyPair(),
      authProvider,
      platformUrl: 'http://example.com',
    });

    const encryptParams = {
      ...new TDF.EncryptParamsBuilder().withStringSource('hello world').withAutoconfigure().build(),
      scope: {
        attributes: [attributeValueFqn, attributeOnlyFqn],
      },
    };

    try {
      const stream = await client.encrypt(encryptParams);
      assert.ok(stream);
      assert.equal(fetchStub.callCount, 1, 'fetch should only be called for FQN hydration');

      const cachedValueKey = findEntryInCache(
        client.kasKeyInfoCache,
        kasValueUri,
        'rsa:2048',
        'value-kid-1'
      );
      const cachedAttributeKey = findEntryInCache(
        client.kasKeyInfoCache,
        kasAttributeUri,
        'rsa:2048',
        'attr-kid-1'
      );
      assert(cachedValueKey !== null, 'value-level key should be cached');
      assert(cachedAttributeKey !== null, 'attribute-level key should be cached');
      const policy = JSON.parse(base64.decode(stream.manifest.encryptionInformation.policy));
      const dataAttributes = policy?.body?.dataAttributes ?? [];
      assert.deepEqual(
        dataAttributes.map((attr: { attribute: string }) => attr.attribute).sort(),
        [attributeValueFqn, attributeOnlyFqn].sort(),
        'policy should include both attributes'
      );

      const keyAccess = stream.manifest.encryptionInformation.keyAccess;
      assert.equal(keyAccess.length, 2, 'manifest should include both key access objects');
      assert.deepInclude(
        keyAccess.map((kao) => ({ url: kao.url, kid: kao.kid })),
        { url: kasValueUri, kid: 'value-kid-1' }
      );
      assert.deepInclude(
        keyAccess.map((kao) => ({ url: kao.url, kid: kao.kid })),
        { url: kasAttributeUri, kid: 'attr-kid-1' }
      );
    } finally {
      fetchStub.restore();
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
  it('always returns a list of obligations', async function () {
    const pt = new TextEncoder().encode('hello world');
    const stream = new DecoratedReadableStream({
      start(controller) {
        controller.enqueue(pt);
        controller.close();
      },
    });
    assert.isEmpty(stream.obligations());
    const obligations = ['https://example.com/obl/example/value/obligated_behavior'];
    // replicate an assignment during the decrypt flow
    stream.requiredObligations = obligations;
    assert.deepEqual(stream.obligations(), obligations);
  });
});
