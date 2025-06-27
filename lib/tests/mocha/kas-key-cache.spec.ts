import { expect, assert } from 'chai';
import sinon from 'sinon';
import { Client, findEntryInCache, HttpRequest } from '../../tdf3/src/client/index.js';
import { getMocks } from '../mocks/index.js';
import { EncryptParams, EncryptParamsBuilder } from '../../tdf3/src/client/builders.js';
import { KasPublicKeyInfo } from '../../src/access.js';
import { pemToCryptoPublicKey } from '../../src/utils.js';
import { valClassA, valueFor } from '../web/policy/mock-attrs.js';
import { KeyAccessServer } from '../../src/policy/attributes.js';
import { SourceType, Value } from '../../src/platform/policy/objects_pb.js';

const Mocks = getMocks();
const kasUrl = 'http://localhost:3000/kas';
const platformUrl = 'http://localhost:3000';

const authProvider = {
  updateClientPublicKey: async () => {},
  withCreds: async (httpReq: HttpRequest) => ({
    ...httpReq,
    headers: { ...httpReq.headers, Authorization: 'Bearer dummy-auth-token' },
  }),
};

const createFakeResponse = (body: unknown, ok = true, status = 200) => {
  const bodyString = JSON.stringify(body);
  return Promise.resolve({
    ok,
    status,
    headers: new Headers({ 'Content-Type': 'application/json' }),
    json: () => Promise.resolve(JSON.parse(bodyString)),
    text: () => Promise.resolve(bodyString),
  } as Response);
};

describe('Client Caching Behavior', () => {
  let client: Client;
  let fetchStub: sinon.SinonStub;

  beforeEach(async () => {
    client = new Client({
      kasEndpoint: kasUrl,
      platformUrl: platformUrl,
      dpopKeys: Mocks.entityKeyPair(),
      clientId: 'id',
      authProvider,
    });
    fetchStub = sinon.stub(globalThis, 'fetch');
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('when using default KAS endpoint', () => {
    it('should not fetch KAS public key if it is already in the cache', async () => {
      const mockPublicKeyResponse: KasPublicKeyInfo = {
        algorithm: 'rsa:2048',
        key: pemToCryptoPublicKey(Mocks.kasPublicKey),
        kid: 'kas-ca-kid-rsa',
        publicKey: Mocks.kasPublicKey,
        url: 'https://kas.ca/kas',
      };

      fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
      fetchStub.onCall(2).returns(createFakeResponse(mockPublicKeyResponse));
      fetchStub.onCall(5).returns(createFakeResponse(mockPublicKeyResponse));

      const cacheSpy = sinon.spy(client, '_doFetchKasKeyWithCache');

      await client.encrypt(
        new EncryptParamsBuilder()
          .withStringSource('some data to encrypt')
          .withAutoconfigure()
          .build()
      );

      expect(Object.keys(client.kasKeyInfoCache)).to.have.lengthOf(1);
      const initialFetchCount = fetchStub.callCount;

      await client.encrypt(
        new EncryptParamsBuilder()
          .withStringSource('some other data to encrypt')
          .withAutoconfigure()
          .build()
      );

      assert.isTrue(
        cacheSpy.callCount === 2,
        '_doFetchKasKeyWithCache should be called a second time'
      );
      assert.equal(
        fetchStub.callCount,
        initialFetchCount,
        'fetch call count should not increase on cache hit'
      );
    });
  });

  describe('when using autoconfigure with attributes', () => {
    it('should only fetch keys for KASes not already in the cache', async () => {
      const kasAuUri = 'https://kas.au/kas';
      const kasCaUri = 'https://kas.ca/kas';
      const kasUsUri = 'https://kas.us/kas';

      const mockKasAuKeyResponse: KasPublicKeyInfo = {
        algorithm: 'ec:secp256r1',
        key: pemToCryptoPublicKey(Mocks.entityECPublicKey),
        kid: 'kas-au-kid-ec',
        publicKey: Mocks.entityECPublicKey,
        url: 'https://kas.au/kas',
      };
      const mockKasCaKeyResponse: KasPublicKeyInfo = {
        algorithm: 'rsa:2048',
        key: pemToCryptoPublicKey(Mocks.kasPublicKey),
        kid: 'kas-ca-kid-rsa',
        publicKey: Mocks.kasPublicKey,
        url: 'https://kas.ca/kas',
      };
      const mockKasUsKeyResponse: KasPublicKeyInfo = {
        algorithm: 'ec:secp256r1',
        key: pemToCryptoPublicKey(Mocks.extraECPublicKey),
        kid: 'kas-us-kid-ec',
        publicKey: Mocks.extraECPublicKey,
        url: 'https://kas.us/kas',
      };

      fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
      fetchStub.onCall(2).returns(createFakeResponse(mockKasAuKeyResponse));
      fetchStub.onCall(5).returns(createFakeResponse(mockKasCaKeyResponse));
      fetchStub.onCall(8).returns(createFakeResponse(mockKasUsKeyResponse));

      const cacheSpy = sinon.spy(client, '_doFetchKasKeyWithCache');

      const encryptParams1: EncryptParams = {
        ...new EncryptParamsBuilder()
          .withStringSource('some data to encrypt')
          .withAutoconfigure()
          .build(),
        splitPlan: [
          { kas: kasAuUri, sid: '1' },
          { kas: kasCaUri, sid: '1' },
        ],
      };
      await client.encrypt(encryptParams1);

      assert.isTrue(
        cacheSpy.calledTwice,
        '_doFetchKasKeyWithCache should be called twice initially'
      );
      assert.isAtLeast(fetchStub.callCount, 2, 'fetch should be called at least twice');
      expect(Object.keys(client.kasKeyInfoCache)).to.have.lengthOf(2);
      const fetchCountAfterFirstEncrypt = fetchStub.callCount;

      const encryptParams2: EncryptParams = {
        ...new EncryptParamsBuilder().withStringSource('some other data to encrypt').build(),
        splitPlan: [
          { kas: kasCaUri, sid: '1' }, // This one is cached
          { kas: kasUsUri, sid: '2' }, // This one is new
        ],
      };
      await client.encrypt(encryptParams2);

      assert.equal(
        cacheSpy.callCount,
        4,
        '_doFetchKasKeyWithCache should be called two more times'
      );
      // Additional 3 calls for base key + RPC + HTTP
      assert.equal(
        fetchStub.callCount,
        fetchCountAfterFirstEncrypt + 3,
        'fetch call count should increase for the new KAS'
      );
      expect(Object.keys(client.kasKeyInfoCache)).to.have.lengthOf(3);
    });
  });

  describe('when using attributeValues with embedded keys', () => {
    it('should pre-populate the cache from attributes and only fetch non-pre-populated keys', async () => {
      const kasPrepopulatedUri = 'https://prepopulated.com/kas';
      const kasFetchedUri = 'https://fetched.com/kas';

      // 1. Define the attribute that contains a pre-populated KAS key.
      // This simulates data coming from a policy service that includes the key material.
      const prepopulatedAttributeValue: Value = {
        $typeName: 'policy.Value',
        fqn: 'http://example.com/attr/prepopulated/value/one',
        kasKeys: [
          {
            $typeName: 'policy.SimpleKasKey',
            kasId: 'prepopulated-kas-1',
            kasUri: kasPrepopulatedUri,
            publicKey: {
              $typeName: 'policy.SimpleKasPublicKey',
              pem: Mocks.kasPublicKey, // The key to be pre-populated
              kid: 'prepopulated-kid',
              algorithm: 1, // Corresponds to Algorithm.RSA_2048
            },
          },
        ],
        // Add other required Value properties with empty/default values
        id: 'value-id-1',
        attribute: {
          $typeName: 'policy.Attribute',
          id: 'attr-id-1',
          name: 'prepopulated',
          fqn: 'http://example.com/attr/prepopulated',
          rule: 0,
          values: [],
          grants: [],
          kasKeys: [],
        },
        value: 'one',
        grants: [],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };
      const fetchedAttributeValue: Value = valueFor(valClassA);
      fetchedAttributeValue.grants.push({
        $typeName: 'policy.KeyAccessServer',
        id: kasFetchedUri,
        kasKeys: [],
        uri: kasFetchedUri,
        publicKey: {
          $typeName: 'policy.PublicKey',
          publicKey: {
            case: 'remote',
            value: kasFetchedUri,
          },
        },
        sourceType: SourceType.EXTERNAL,
        name: kasFetchedUri,
      } as KeyAccessServer);

      // 2. Define the key that we expect the client to fetch over the network.
      const mockKasFetchedKeyResponse: KasPublicKeyInfo = {
        algorithm: 'ec:secp256r1',
        key: pemToCryptoPublicKey(Mocks.entityECPublicKey),
        kid: 'fetched-kid',
        publicKey: Mocks.entityECPublicKey,
        url: kasFetchedUri,
      };

      // 3. Set up the fetch stub. It should only succeed for the *fetched* key.
      // If the code tries to fetch the prepopulated key, it will get a 404, causing a failure.
      fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
      fetchStub.onCall(2).returns(createFakeResponse(mockKasFetchedKeyResponse)); // Succeeds on 3rd attempt

      // const cacheSpy = sinon.spy(client, '_doFetchKasKeyWithCache');

      const encryptParams: EncryptParams = {
        ...new EncryptParamsBuilder()
          .withStringSource('some data to encrypt')
          .withAutoconfigure()
          .build(),
        // Provide both the attribute with the embedded key.
        scope: {
          attributeValues: [prepopulatedAttributeValue, fetchedAttributeValue],
        },
      };

      await client.encrypt(encryptParams);

      const cachedEntry = findEntryInCache(
        client.kasKeyInfoCache,
        kasPrepopulatedUri,
        'rsa:2048',
        undefined
      );
      assert(cachedEntry !== null, 'Key should be cached');

      assert.equal(
        fetchStub.callCount,
        3,
        'fetch was only called 3 times (base key, RPC, HTTP) for the one non-prepopulated key'
      );
    });

    it('should handle multiple pre-populated keys with different KIDs for the same KAS', async () => {
      const kasSameUri = 'https://same-kas.com/kas';

      // 1. Define an attribute value that contains a KAS with two different EC keys (and KIDs).
      const attributeWithMultipleKeys: Value = {
        $typeName: 'policy.Value',
        fqn: 'http://example.com/attr/multi-key/value/one',
        kasKeys: [
          {
            $typeName: 'policy.SimpleKasKey',
            kasId: 'same-kas-id-1',
            kasUri: kasSameUri,
            publicKey: {
              $typeName: 'policy.SimpleKasPublicKey',
              pem: Mocks.entityECPublicKey, // First EC key
              kid: 'ec-key-kid-1',
              algorithm: 3, // Corresponds to Algorithm.EC_P256
            },
          },
          {
            $typeName: 'policy.SimpleKasKey',
            kasId: 'same-kas-id-2',
            kasUri: kasSameUri,
            publicKey: {
              $typeName: 'policy.SimpleKasPublicKey',
              pem: Mocks.extraECPublicKey, // Second EC key
              kid: 'ec-key-kid-2',
              algorithm: 3, // Corresponds to Algorithm.EC_P256
            },
          },
        ],
        // Boilerplate for the Value type
        id: 'value-id-multi',
        attribute: {
          $typeName: 'policy.Attribute',
          id: 'attr-id-multi',
          name: 'multi-key',
          fqn: 'http://example.com/attr/multi-key',
          rule: 0,
          values: [],
          grants: [],
          kasKeys: [],
        },
        value: 'one',
        grants: [],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };

      fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
      const cacheSpy = sinon.spy(client, '_doFetchKasKeyWithCache');

      const encryptParams: EncryptParams = {
        ...new EncryptParamsBuilder()
          .withStringSource('some data to encrypt')
          .withAutoconfigure()
          .build(),
        scope: {
          attributeValues: [attributeWithMultipleKeys],
        },
      };

      await client.encrypt(encryptParams);

      assert.isTrue(cacheSpy.calledTwice, 'cache method was called for both keys in splitPlan');
      assert.equal(fetchStub.callCount, 0, 'fetch should not be called at all');

      // Verify both keys are in the cache, distinguished by their KID.
      const cachedEntry1 = findEntryInCache(
        client.kasKeyInfoCache,
        kasSameUri,
        'ec:secp256r1',
        'ec-key-kid-1'
      );
      const cachedEntry2 = findEntryInCache(
        client.kasKeyInfoCache,
        kasSameUri,
        'ec:secp256r1',
        'ec-key-kid-2'
      );

      assert(cachedEntry1 !== null, 'First key (kid-1) should be in the cache');
      assert(cachedEntry2 !== null, 'Second key (kid-2) should be in the cache');
    });

    it('should pre-populate the cache from two different attributeValues', async () => {
      const kasSameUri = 'https://two-attrs.com/kas';

      // 1. Define the first attributeValue with one EC key.
      const attributeValue1: Value = {
        $typeName: 'policy.Value',
        fqn: 'http://example.com/attr/two-attrs/value/val1',
        kasKeys: [
          {
            $typeName: 'policy.SimpleKasKey',
            kasId: 'two-attrs-kas-1',
            kasUri: kasSameUri,
            publicKey: {
              $typeName: 'policy.SimpleKasPublicKey',
              pem: Mocks.entityECPublicKey, // First EC key
              kid: 'two-attrs-kid-1',
              algorithm: 3, // Corresponds to Algorithm.EC_P256
            },
          },
        ],
        // Boilerplate
        id: 'value-id-two-attrs-1',
        attribute: {
          $typeName: 'policy.Attribute',
          id: 'attr-id-two-attrs',
          name: 'two-attrs',
          fqn: 'http://example.com/attr/two-attrs',
          rule: 0,
          values: [],
          grants: [],
          kasKeys: [],
        },
        value: 'val1',
        grants: [],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };

      // 2. Define the second attributeValue with a different EC key for the same KAS.
      const attributeValue2: Value = {
        $typeName: 'policy.Value',
        fqn: 'http://example.com/attr/two-attrs/value/val2',
        kasKeys: [
          {
            $typeName: 'policy.SimpleKasKey',
            kasId: 'two-attrs-kas-2',
            kasUri: kasSameUri,
            publicKey: {
              $typeName: 'policy.SimpleKasPublicKey',
              pem: Mocks.extraECPublicKey, // Second EC key
              kid: 'two-attrs-kid-2',
              algorithm: 3, // Corresponds to Algorithm.EC_P256
            },
          },
        ],
        // Boilerplate
        id: 'value-id-two-attrs-2',
        attribute: attributeValue1.attribute, // Share the same parent attribute
        value: 'val2',
        grants: [],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };

      // Set up the fetch stub to always fail.
      // This proves no network calls are made.
      fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
      const cacheSpy = sinon.spy(client, '_doFetchKasKeyWithCache');

      const encryptParams: EncryptParams = {
        ...new EncryptParamsBuilder()
          .withStringSource('some data to encrypt')
          .withAutoconfigure()
          .build(),
        scope: {
          // Provide both attribute values.
          attributeValues: [attributeValue1, attributeValue2],
        },
      };

      await client.encrypt(encryptParams);

      assert.isTrue(cacheSpy.calledTwice, 'cache method was called once for the splitPlan');
      assert.equal(fetchStub.callCount, 0, 'fetch should not be called');

      // Verify both keys are in the cache, distinguished by their KID.
      const cachedEntry1 = findEntryInCache(
        client.kasKeyInfoCache,
        kasSameUri,
        'ec:secp256r1',
        'two-attrs-kid-1'
      );
      const cachedEntry2 = findEntryInCache(
        client.kasKeyInfoCache,
        kasSameUri,
        'ec:secp256r1',
        'two-attrs-kid-2'
      );
      assert(cachedEntry1 !== null, 'First key (kid-1) from attribute 1 should be in the cache');
      assert(cachedEntry2 !== null, 'Second key (kid-2) from attribute 2 should be in the cache');
    });
  });
});
