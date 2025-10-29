import { create, toJsonString } from '@bufbuild/protobuf';
import {
  UnsignedRewrapRequest_WithPolicyRequestSchema,
  UnsignedRewrapRequestSchema,
} from '../platform/kas/kas_pb.js';
import { generateKeyPair, keyAgreement } from '../nanotdf-crypto/index.js';
import getHkdfSalt from './helpers/getHkdfSalt.js';
import DefaultParams from './models/DefaultParams.js';
import {
  fetchKeyAccessServers,
  fetchWrappedKey,
  KasPublicKeyInfo,
  OriginAllowList,
} from '../access.js';
import { handleRpcRewrapErrorString } from '../../src/access/access-rpc.js';
import { AuthProvider, isAuthProvider, reqSignature } from '../auth/providers.js';
import { ConfigurationError, DecryptError, TdfError, UnsafeUrlError } from '../errors.js';
import {
  cryptoPublicToPem,
  getRequiredObligationFQNs,
  pemToCryptoPublicKey,
  upgradeRewrapResponseV1,
  validateSecureUrl,
  getPlatformUrlFromKasEndpoint,
} from '../utils.js';

export interface ClientConfig {
  allowedKases?: string[];
  fulfillableObligationFQNs?: string[];
  ignoreAllowList?: boolean;
  authProvider: AuthProvider;
  dpopEnabled?: boolean;
  dpopKeys?: Promise<CryptoKeyPair>;
  ephemeralKeyPair?: Promise<CryptoKeyPair>;
  kasEndpoint: string;
  platformUrl: string;
}

type RewrapKeyResult = {
  unwrappedKey: CryptoKey;
  requiredObligations: string[];
};

function toJWSAlg(c: CryptoKey): string {
  const { algorithm } = c;
  switch (algorithm.name) {
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS':
    case 'RSA-OAEP': {
      const r = algorithm as RsaHashedKeyGenParams;
      switch (r.modulusLength) {
        case 2048:
          return 'RS256';
        case 3072:
          return 'RS384';
        case 4096:
          return 'RS512';
      }
      break;
    }
    case 'ECDSA':
    case 'ECDH': {
      return 'ES256';
    }
  }
  throw new ConfigurationError(`unsupported key algorithm ${JSON.stringify(algorithm)}`);
}

async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair();
  if (!privateKey || !publicKey) {
    throw Error('Key pair generation failed');
  }
  return { publicKey, privateKey };
}

async function generateSignerKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    true,
    ['sign', 'verify']
  );
}

/**
 * A Client encapsulates sessions interacting with TDF3 and nanoTDF backends, KAS and any
 * plugin-based sessions like identity and further attribute control. Most importantly, it is responsible
 * for local key and token management, including the ephemeral public/private keypairs
 * used for encrypting and decrypting information.
 *
 * @link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair
 *
 * @example
 * import { Client, clientAuthProvider, decrypt, encrypt } from '@opentdf/sdk/nanotdf`
 *
 * const OIDC_ENDPOINT = 'http://localhost:65432/auth/';
 * const KAS_URL = 'http://localhost:65432/kas';
 *
 * let client = new Client(
 *    await clientAuthProvider({
 *      clientId: 'tdf-client',
 *      clientSecret: '123-456',
 *      oidcOrigin: OIDC_ENDPOINT,
 *    }),
 *    KAS_URL
 *  );
 *
 * // t=1
 * let nanoTDFEncrypted = await encrypt('some string', client.unwrappedKey);
 * let nanoTDFDecrypted = await decrypt(nanoTDFEncrypted, client.unwrappedKey);
 * nanoTDFDecrypted.toString() // 'some string'
 *
 */
export default class Client {
  static readonly KEY_ACCESS_REMOTE = 'remote';
  static readonly KAS_PROTOCOL = 'kas';
  static readonly SDK_INITIAL_RELEASE = '0.0.0';
  static readonly INITIAL_RELEASE_IV_SIZE = 3;
  static readonly IV_SIZE = 12;

  allowedKases?: OriginAllowList;
  readonly fulfillableObligationFQNs: string[];
  /*
    These variables are expected to be either assigned during initialization or within the methods.
    This is needed as the flow is very specific. Errors should be thrown if the necessary step is not completed.
  */
  protected kasUrl: string;
  readonly platformUrl: string;
  kasPubKey?: KasPublicKeyInfo;
  readonly authProvider: AuthProvider;
  readonly dpopEnabled: boolean;
  dissems: string[] = [];
  dataAttributes: string[] = [];
  protected ephemeralKeyPair: Promise<CryptoKeyPair>;
  protected requestSignerKeyPair: Promise<CryptoKeyPair>;
  protected iv?: number;

  /**
   * Create new NanoTDF Client
   *
   * The Ephemeral Key Pair can either be provided or will be generate when fetching the entity object. Once set it
   * cannot be changed. If a new ephemeral key is desired it a new client should be initialized.
   * There is no performance impact for creating a new client IFF the ephemeral key pair is provided.
   */
  constructor(
    optsOrOldAuthProvider: AuthProvider | ClientConfig,
    kasUrl?: string,
    ephemeralKeyPair?: CryptoKeyPair,
    dpopEnabled = false
  ) {
    const enwrapAuthProvider = (a: AuthProvider): AuthProvider => {
      return {
        updateClientPublicKey: async (signingKey) => {
          await a.updateClientPublicKey(signingKey);
        },
        withCreds: async (httpReq) => {
          const signer = await this.requestSignerKeyPair;
          if (!signer) {
            throw new ConfigurationError('failed to find or generate signer session key');
          }
          await a.updateClientPublicKey(signer);
          return a.withCreds(httpReq);
        },
      };
    };
    if (isAuthProvider(optsOrOldAuthProvider)) {
      this.authProvider = enwrapAuthProvider(optsOrOldAuthProvider);
      if (!kasUrl) {
        throw new ConfigurationError('please specify kasEndpoint');
      }
      // TODO Disallow http KAS. For now just log as error
      validateSecureUrl(kasUrl);
      this.kasUrl = kasUrl;
      this.dpopEnabled = dpopEnabled;

      if (ephemeralKeyPair) {
        this.ephemeralKeyPair = Promise.resolve(ephemeralKeyPair);
      } else {
        this.ephemeralKeyPair = generateEphemeralKeyPair();
      }
      this.iv = 1;
    } else {
      const {
        allowedKases,
        fulfillableObligationFQNs = [],
        ignoreAllowList,
        authProvider,
        dpopEnabled,
        dpopKeys,
        ephemeralKeyPair,
        kasEndpoint,
        platformUrl,
      } = optsOrOldAuthProvider;
      this.authProvider = enwrapAuthProvider(authProvider);
      // TODO Disallow http KAS. For now just log as error
      validateSecureUrl(kasEndpoint);
      this.kasUrl = kasEndpoint;
      this.platformUrl = platformUrl;
      if (allowedKases?.length || ignoreAllowList) {
        this.allowedKases = new OriginAllowList(allowedKases || [], ignoreAllowList);
      }
      this.fulfillableObligationFQNs = fulfillableObligationFQNs;
      this.dpopEnabled = !!dpopEnabled;
      if (dpopKeys) {
        this.requestSignerKeyPair = dpopKeys;
      } else {
        this.requestSignerKeyPair = generateSignerKeyPair();
      }

      if (ephemeralKeyPair) {
        this.ephemeralKeyPair = ephemeralKeyPair;
      } else {
        this.ephemeralKeyPair = generateEphemeralKeyPair();
      }
      this.iv = 1;
    }
  }

  /**
   * Add attribute to the TDF file/data
   *
   * @param attribute The attribute that decides the access control of the TDF.
   */
  addAttribute(attribute: string): void {
    this.dataAttributes.push(attribute);
  }

  /**
   * Rewrap key
   *
   * @important the `fetchEntityObject` method must be called prior to
   * @param nanoTdfHeader the full header for the nanotdf
   * @param kasRewrapUrl key access server's rewrap endpoint
   * @param magicNumberVersion nanotdf container version
   * @param clientVersion version of the client, as SemVer
   */
  async rewrapKey(
    nanoTdfHeader: ArrayBufferLike,
    kasRewrapUrl: string,
    magicNumberVersion: ArrayBufferLike,
    clientVersion: string
  ): Promise<RewrapKeyResult> {
    let allowedKases = this.allowedKases;

    if (!allowedKases) {
      allowedKases = await fetchKeyAccessServers(this.platformUrl, this.authProvider);
    }

    if (!allowedKases.allows(kasRewrapUrl)) {
      throw new UnsafeUrlError(`request URL ∉ ${allowedKases.origins};`, kasRewrapUrl);
    }

    const ephemeralKeyPair = await this.ephemeralKeyPair;
    const requestSignerKeyPair = await this.requestSignerKeyPair;

    // Ensure the ephemeral key pair has been set or generated (see fetchEntityObject)
    if (!ephemeralKeyPair?.privateKey) {
      throw new ConfigurationError('Ephemeral key has not been set or generated');
    }

    if (!requestSignerKeyPair?.privateKey) {
      throw new ConfigurationError('Signer key has not been set or generated');
    }

    const unsignedRequest = create(UnsignedRewrapRequestSchema, {
      clientPublicKey: await cryptoPublicToPem(ephemeralKeyPair.publicKey),
      requests: [
        create(UnsignedRewrapRequest_WithPolicyRequestSchema, {
          keyAccessObjects: [
            {
              keyAccessObjectId: 'kao-0', // only one kao, no bulk
              keyAccessObject: {
                header: new Uint8Array(nanoTdfHeader),
                kasUrl: '',
                protocol: Client.KAS_PROTOCOL,
                keyType: Client.KEY_ACCESS_REMOTE,
              },
            },
          ],
          algorithm: DefaultParams.defaultECAlgorithm,
        }),
      ],
      keyAccess: {
        header: new Uint8Array(nanoTdfHeader),
        kasUrl: '',
        protocol: Client.KAS_PROTOCOL,
        keyType: Client.KEY_ACCESS_REMOTE,
      },
      algorithm: DefaultParams.defaultECAlgorithm,
    });

    const requestBodyStr = toJsonString(UnsignedRewrapRequestSchema, unsignedRequest);

    const jwtPayload = { requestBody: requestBodyStr };

    const signedRequestToken = await reqSignature(jwtPayload, requestSignerKeyPair.privateKey, {
      alg: toJWSAlg(requestSignerKeyPair.publicKey),
    });

    // Wrapped
    const rewrapResp = await fetchWrappedKey(
      kasRewrapUrl,
      signedRequestToken,
      this.authProvider,
      this.fulfillableObligationFQNs
    );
    upgradeRewrapResponseV1(rewrapResp);

    // Assume only one response and one result for now (V1 style)
    const result = rewrapResp.responses[0].results[0];
    let entityWrappedKey: Uint8Array<ArrayBufferLike>;
    switch (result.result.case) {
      case 'kasWrappedKey': {
        entityWrappedKey = result.result.value;
        break;
      }
      case 'error': {
        handleRpcRewrapErrorString(
          result.result.value,
          getPlatformUrlFromKasEndpoint(kasRewrapUrl)
        );
      }
      default: {
        throw new DecryptError('KAS rewrap response missing wrapped key');
      }
    }

    // Upgrade any V1 responses to V2
    upgradeRewrapResponseV1(rewrapResp);

    const result = rewrapResp.responses?.[0]?.results?.[0];
    if (!result) {
      // This should not happen - KAS should always return at least one response and one result
      // or the upgradeRewrapResponseV1 should have created them
      throw new DecryptError('KAS rewrap response missing expected response or result');
    }

    let entityWrappedKey: Uint8Array<ArrayBufferLike>;
    switch (result.result.case) {
      case 'kasWrappedKey': {
        entityWrappedKey = result.result.value;
        break;
      }
      case 'error': {
        handleRpcRewrapErrorString(
          result.result.value,
          getPlatformUrlFromKasEndpoint(kasRewrapUrl)
        );
      }
      default: {
        throw new DecryptError('KAS rewrap response missing wrapped key');
      }
    }

    // Extract the iv and ciphertext
    const ivLength =
      clientVersion == Client.SDK_INITIAL_RELEASE ? Client.INITIAL_RELEASE_IV_SIZE : Client.IV_SIZE;
    const iv = entityWrappedKey.subarray(0, ivLength);
    const encryptedSharedKey = entityWrappedKey.subarray(ivLength);

    let kasPublicKey;
    try {
      // Let us import public key as a cert or public key
      kasPublicKey = await pemToCryptoPublicKey(rewrapResp.sessionPublicKey);
    } catch (cause) {
      throw new ConfigurationError(
        `internal: [${kasRewrapUrl}] PEM Public Key to crypto public key failed. Is PEM formatted correctly?`,
        cause
      );
    }

    let hkdfSalt;
    try {
      // Get the hkdf salt params
      hkdfSalt = await getHkdfSalt(magicNumberVersion);
    } catch (e) {
      throw new TdfError('salting hkdf failed', e);
    }
    const { privateKey } = await this.ephemeralKeyPair;

    // Get the unwrapping key
    let unwrappingKey;
    try {
      unwrappingKey = await keyAgreement(
        // Ephemeral private key
        privateKey,
        kasPublicKey,
        hkdfSalt
      );
    } catch (e) {
      if (e.name == 'InvalidAccessError' || e.name == 'OperationError') {
        throw new DecryptError('unable to solve key agreement', e);
      } else if (e.name == 'NotSupported') {
        throw new ConfigurationError('unable to unwrap key from kas', e);
      }
      throw new TdfError('unable to reach agreement', e);
    }

    const authTagLength = 8 * (encryptedSharedKey.byteLength - 32);
    let decryptedKey;
    try {
      // Decrypt the wrapped key
      decryptedKey = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: authTagLength },
        unwrappingKey,
        encryptedSharedKey
      );
    } catch (cause) {
      throw new DecryptError(
        `unable to decrypt key. Are you using the right KAS? Is the salt correct?`,
        cause
      );
    }

    // UnwrappedKey
    let unwrappedKey;
    try {
      unwrappedKey = await crypto.subtle.importKey(
        'raw',
        decryptedKey,
        'AES-GCM',
        // @security This allows the key to be used in `exportKey` and `wrapKey`
        // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
        // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey
        true,
        // Want to use the key to encrypt and decrypt. Signing key will be used later.
        ['encrypt', 'decrypt']
      );
    } catch (cause) {
      throw new DecryptError('Unable to import raw key.', cause);
    }

    return {
      requiredObligations: getRequiredObligationFQNs(rewrapResp),
      unwrappedKey: unwrappedKey,
    };
  }
}
