import { assert } from 'chai';
import sinon from 'sinon';
import { Client, HttpRequest } from '../../tdf3/src/client/index.js';
import { getMocks } from '../mocks/index.js';
import { EncryptParamsBuilder } from '../../tdf3/src/client/builders.js';
import { GetAttributeValuesByFqnsResponse } from '../../src/platform/policy/attributes/attributes_pb.js';
import {
  Attribute,
  AttributeRuleType,
  KeyAccessServer,
  Namespace,
  Value,
} from '../../src/policy/attributes.js';
import { SourceType } from '../../src/platform/policy/objects_pb.js';
import { KasPublicKeyInfo } from '../../src/access.js';
import { pemToCryptoPublicKey } from '../../src/utils.js';

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

// const _createFakeResponse = (body: unknown, ok = true, status = 200) => {
//   const bodyString = JSON.stringify(body);
//   return Promise.resolve({
//     ok,
//     status,
//     headers: new Headers({ 'Content-Type': 'application/json' }),
//     json: () => Promise.resolve(JSON.parse(bodyString)),
//     text: () => Promise.resolve(bodyString),
//   } as Response);
// };

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

  describe('attributeValues with cached keys', () => {
    describe('same kids, different uri', () => {
      it('should create multiple splits for ALL_OF', async () => {
        const nsOne: Namespace = {
          $typeName: 'policy.Namespace',
          fqn: 'https://ns-one.example',
          name: 'ns-one.example',
          active: true,
          grants: [],
          id: 'ns-one.example',
          kasKeys: [],
        };

        const kasOne: KeyAccessServer = {
          $typeName: 'policy.KeyAccessServer',
          id: 'kas-one-id',
          kasKeys: [],
          uri: 'https://kas-one.example/kas',
          publicKey: {
            $typeName: 'policy.PublicKey',
            remote: 'https://kas-one.example/kas',
          } as unknown as KeyAccessServer['publicKey'],
          sourceType: SourceType.EXTERNAL,
          name: 'kas-one.example',
        };
        const kasTwo: KeyAccessServer = {
          $typeName: 'policy.KeyAccessServer',
          id: 'kas-two-id',
          kasKeys: [],
          uri: 'https://kas-two.example/kas',
          publicKey: {
            remote: 'https://kas-two.example/kas',
          } as unknown as KeyAccessServer['publicKey'],
          sourceType: SourceType.EXTERNAL,
          name: 'kas-two.example',
        };

        const attrOne: Attribute = {
          fqn: 'https://kas-one.example/attr/attr-to-test',
          namespace: nsOne,
          active: true,
          name: 'Classification',
          rule: AttributeRuleType.ALL_OF,
          $typeName: 'policy.Attribute',
          grants: [],
          id: 'attr-one-id',
          kasKeys: [],
          values: [],
        };

        const attrOneValueOneKey = {
          algorithm: 'ec:secp256r1',
          key: pemToCryptoPublicKey(Mocks.entityECPublicKey),
          kid: 'same-kid-as-other-keys',
          publicKey: Mocks.entityECPublicKey,
          url: kasOne.uri,
        } satisfies KasPublicKeyInfo;
        const attrOneValueTwoKey = {
          algorithm: 'ec:secp256r1',
          key: pemToCryptoPublicKey(Mocks.extraECPublicKey),
          kid: 'same-kid-as-other-keys',
          publicKey: Mocks.extraECPublicKey,
          url: kasTwo.uri,
        } satisfies KasPublicKeyInfo;

        const attrOneValueOne: Value = {
          $typeName: 'policy.Value',
          fqn: 'https://kas-one.example/attr/attr-to-test/value/one',
          kasKeys: [
            {
              $typeName: 'policy.SimpleKasKey',
              kasId: kasOne.id,
              kasUri: kasOne.uri,
              publicKey: {
                $typeName: 'policy.SimpleKasPublicKey',
                algorithm: 3,
                kid: attrOneValueOneKey.kid,
                pem: attrOneValueOneKey.publicKey,
              },
            },
          ],
          id: 'attr-value-one-id',
          attribute: attrOne,
          value: 'one',
          grants: [],
          active: true,
          subjectMappings: [],
          resourceMappings: [],
        };
        const attrOneValueTwo: Value = {
          $typeName: 'policy.Value',
          fqn: 'https://kas-one.example/attr/attr-to-test/value/two',
          kasKeys: [
            {
              $typeName: 'policy.SimpleKasKey',
              kasId: kasTwo.id,
              kasUri: kasTwo.uri,
              publicKey: {
                $typeName: 'policy.SimpleKasPublicKey',
                algorithm: 3,
                kid: attrOneValueTwoKey.kid,
                pem: attrOneValueTwoKey.publicKey,
              },
            },
          ],
          id: 'attr-value-two-id',
          attribute: attrOne,
          value: 'two',
          grants: [],
          active: true,
          subjectMappings: [],
          resourceMappings: [],
        };

        const attrValueByFqnResponse: GetAttributeValuesByFqnsResponse = {
          $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse',
          fqnAttributeValues: {
            [attrOneValueOne.fqn]: {
              $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue',
              attribute: attrOne,
              value: attrOneValueOne,
            },
            [attrOneValueTwo.fqn]: {
              $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue',
              attribute: attrOne,
              value: attrOneValueTwo,
            },
          },
        };

        fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
        fetchStub.onCall(0).returns(createFakeResponse(attrValueByFqnResponse));
        fetchStub.onCall(3).returns(createFakeResponse(attrOneValueOneKey));
        fetchStub.onCall(6).returns(createFakeResponse(attrOneValueTwoKey));

        const encryptParams = new EncryptParamsBuilder()
          .withStringSource('some data to encrypt')
          .withAttributes([attrOneValueOne.fqn, attrOneValueTwo.fqn])
          .withAutoconfigure()
          .build();

        const stream = await client.encrypt(encryptParams);
        assert(
          stream.manifest.encryptionInformation.keyAccess.length === 2,
          'Should have 2 items in KAO'
        );
      });
    });

    it('should create multiple splits for ALL_OF', async () => {
      const nsOne: Namespace = {
        $typeName: 'policy.Namespace',
        fqn: 'https://ns-one.example',
        name: 'ns-one.example',
        active: true,
        grants: [],
        id: 'ns-one.example',
        kasKeys: [],
      };

      const kasOne: KeyAccessServer = {
        $typeName: 'policy.KeyAccessServer',
        id: 'kas-one-id',
        kasKeys: [],
        uri: 'https://kas-one.example/kas',
        publicKey: {
          $typeName: 'policy.PublicKey',
          remote: 'https://kas-one.example/kas',
        } as unknown as KeyAccessServer['publicKey'],
        sourceType: SourceType.EXTERNAL,
        name: 'kas-one.example',
      };
      const kasTwo: KeyAccessServer = {
        $typeName: 'policy.KeyAccessServer',
        id: 'kas-two-id',
        kasKeys: [],
        uri: 'https://kas-two.example/kas',
        publicKey: {
          remote: 'https://kas-two.example/kas',
        } as unknown as KeyAccessServer['publicKey'],
        sourceType: SourceType.EXTERNAL,
        name: 'kas-two.example',
      };

      const attrOne: Attribute = {
        fqn: 'https://kas-one.example/attr/attr-to-test',
        namespace: nsOne,
        active: true,
        name: 'Classification',
        rule: AttributeRuleType.ALL_OF,
        $typeName: 'policy.Attribute',
        grants: [],
        id: 'attr-one-id',
        kasKeys: [],
        values: [],
      };

      const attrOneValueOneKey = {
        algorithm: 'ec:secp256r1',
        key: pemToCryptoPublicKey(Mocks.entityECPublicKey),
        kid: 'attr-one-value-one-key',
        publicKey: Mocks.entityECPublicKey,
        url: kasOne.uri,
      } satisfies KasPublicKeyInfo;
      const attrOneValueTwoKey = {
        algorithm: 'ec:secp256r1',
        key: pemToCryptoPublicKey(Mocks.extraECPublicKey),
        kid: 'attr-one-value-two-key',
        publicKey: Mocks.extraECPublicKey,
        url: kasTwo.uri,
      } satisfies KasPublicKeyInfo;

      const attrOneValueOne: Value = {
        $typeName: 'policy.Value',
        fqn: 'https://kas-one.example/attr/attr-to-test/value/one',
        kasKeys: [
          {
            $typeName: 'policy.SimpleKasKey',
            kasId: kasOne.id,
            kasUri: kasOne.uri,
            publicKey: {
              $typeName: 'policy.SimpleKasPublicKey',
              algorithm: 3,
              kid: attrOneValueOneKey.kid,
              pem: attrOneValueOneKey.publicKey,
            },
          },
        ],
        id: 'attr-value-one-id',
        attribute: attrOne,
        value: 'one',
        grants: [],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };
      const attrOneValueTwo: Value = {
        $typeName: 'policy.Value',
        fqn: 'https://kas-one.example/attr/attr-to-test/value/two',
        kasKeys: [
          {
            $typeName: 'policy.SimpleKasKey',
            kasId: kasTwo.id,
            kasUri: kasTwo.uri,
            publicKey: {
              $typeName: 'policy.SimpleKasPublicKey',
              algorithm: 3,
              kid: attrOneValueTwoKey.kid,
              pem: attrOneValueTwoKey.publicKey,
            },
          },
        ],
        id: 'attr-value-two-id',
        attribute: attrOne,
        value: 'two',
        grants: [],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };

      const attrValueByFqnResponse: GetAttributeValuesByFqnsResponse = {
        $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse',
        fqnAttributeValues: {
          [attrOneValueOne.fqn]: {
            $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue',
            attribute: attrOne,
            value: attrOneValueOne,
          },
          [attrOneValueTwo.fqn]: {
            $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue',
            attribute: attrOne,
            value: attrOneValueTwo,
          },
        },
      };

      fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
      fetchStub.onCall(0).returns(createFakeResponse(attrValueByFqnResponse));
      fetchStub.onCall(3).returns(createFakeResponse(attrOneValueOneKey));
      fetchStub.onCall(6).returns(createFakeResponse(attrOneValueTwoKey));

      const encryptParams = new EncryptParamsBuilder()
        .withStringSource('some data to encrypt')
        .withAttributes([attrOneValueOne.fqn, attrOneValueTwo.fqn])
        .withAutoconfigure()
        .build();

      const stream = await client.encrypt(encryptParams);
      assert(
        stream.manifest.encryptionInformation.keyAccess.length === 2,
        'Should have 2 items in KAO'
      );
    });
  });

  describe('attributeValues with grants', () => {
    it('should create multiple splits for ALL_OF', async () => {
      const nsOne: Namespace = {
        $typeName: 'policy.Namespace',
        fqn: 'https://ns-one.example',
        name: 'ns-one.example',
        active: true,
        grants: [],
        id: 'ns-one.example',
        kasKeys: [],
      };

      const kasOne: KeyAccessServer = {
        $typeName: 'policy.KeyAccessServer',
        id: 'kas-one-id',
        kasKeys: [],
        uri: 'https://kas-one.example/kas',
        publicKey: {
          $typeName: 'policy.PublicKey',
          remote: 'https://kas-one.example/kas',
        } as unknown as KeyAccessServer['publicKey'],
        sourceType: SourceType.EXTERNAL,
        name: 'kas-one.example',
      };
      const kasTwo: KeyAccessServer = {
        $typeName: 'policy.KeyAccessServer',
        id: 'kas-two-id',
        kasKeys: [],
        uri: 'https://kas-two.example/kas',
        publicKey: {
          remote: 'https://kas-two.example/kas',
        } as unknown as KeyAccessServer['publicKey'],
        sourceType: SourceType.EXTERNAL,
        name: 'kas-two.example',
      };

      const attrOne: Attribute = {
        fqn: 'https://kas-one.example/attr/attr-to-test',
        namespace: nsOne,
        active: true,
        name: 'Classification',
        rule: AttributeRuleType.ALL_OF,
        $typeName: 'policy.Attribute',
        grants: [],
        id: 'attr-one-id',
        kasKeys: [],
        values: [],
      };

      const attrOneValueOne: Value = {
        $typeName: 'policy.Value',
        fqn: 'https://kas-one.example/attr/attr-to-test/value/one',
        kasKeys: [],
        id: 'attr-value-one-id',
        attribute: attrOne,
        value: 'one',
        grants: [kasOne],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };
      const attrOneValueTwo: Value = {
        $typeName: 'policy.Value',
        fqn: 'https://kas-one.example/attr/attr-to-test/value/two',
        kasKeys: [],
        id: 'attr-value-two-id',
        attribute: attrOne,
        value: 'two',
        grants: [kasTwo],
        active: true,
        subjectMappings: [],
        resourceMappings: [],
      };

      const attrValueByFqnResponse: GetAttributeValuesByFqnsResponse = {
        $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse',
        fqnAttributeValues: {
          [attrOneValueOne.fqn]: {
            $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue',
            attribute: attrOne,
            value: attrOneValueOne,
          },
          [attrOneValueTwo.fqn]: {
            $typeName: 'policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue',
            attribute: attrOne,
            value: attrOneValueTwo,
          },
        },
      };

      const attrOneValueOneKey: KasPublicKeyInfo = {
        algorithm: 'ec:secp256r1',
        key: pemToCryptoPublicKey(Mocks.entityECPublicKey),
        kid: 'attr-one-value-one-key',
        publicKey: Mocks.entityECPublicKey,
        url: kasOne.uri,
      };
      const attrOneValueTwoKey: KasPublicKeyInfo = {
        algorithm: 'ec:secp256r1',
        key: pemToCryptoPublicKey(Mocks.extraECPublicKey),
        kid: 'attr-one-value-two-key',
        publicKey: Mocks.extraECPublicKey,
        url: kasTwo.uri,
      };

      fetchStub.returns(createFakeResponse({ error: 'Not Found' }, false, 404));
      fetchStub.onCall(0).returns(createFakeResponse(attrValueByFqnResponse));
      fetchStub.onCall(3).returns(createFakeResponse(attrOneValueOneKey));
      fetchStub.onCall(6).returns(createFakeResponse(attrOneValueTwoKey));

      const encryptParams = new EncryptParamsBuilder()
        .withStringSource('some data to encrypt')
        .withAttributes([attrOneValueOne.fqn, attrOneValueTwo.fqn])
        .withAutoconfigure()
        .build();

      const stream = await client.encrypt(encryptParams);
      assert(
        stream.manifest.encryptionInformation.keyAccess.length === 2,
        'Should have 2 items in KAO'
      );
    });
  });
});
