import { type TypedArray } from '../tdf/TypedArray.js';
import * as base64 from '../encodings/base64.js';
import { generateKeyPair, keyAgreement } from '../nanotdf-crypto/index.js';
import getHkdfSalt from './helpers/getHkdfSalt.js';
import DefaultParams from './models/DefaultParams.js';
import { fetchWrappedKey, KasPublicKeyInfo, OriginAllowList } from '../access.js';
import { AuthProvider, isAuthProvider, reqSignature } from '../auth/providers.js';
import { ConfigurationError, DecryptError, TdfError, UnsafeUrlError } from '../errors.js';
import { cryptoPublicToPem, pemToCryptoPublicKey, validateSecureUrl } from '../utils.js';

export interface ClientConfig {
  allowedKases?: string[];
  ignoreAllowList?: boolean;
  authProvider: AuthProvider;
  dpopEnabled?: boolean;
  dpopKeys?: Promise<CryptoKeyPair>;
  ephemeralKeyPair?: Promise<CryptoKeyPair>;
  kasEndpoint: string;
}

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

  allowedKases: OriginAllowList;
  /*
    These variables are expected to be either assigned during initialization or within the methods.
    This is needed as the flow is very specific. Errors should be thrown if the necessary step is not completed.
  */
  protected kasUrl: string;
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
      this.allowedKases = new OriginAllowList([kasUrl]);
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
        ignoreAllowList,
        authProvider,
        dpopEnabled,
        dpopKeys,
        ephemeralKeyPair,
        kasEndpoint,
      } = optsOrOldAuthProvider;
      this.authProvider = enwrapAuthProvider(authProvider);
      // TODO Disallow http KAS. For now just log as error
      validateSecureUrl(kasEndpoint);
      this.kasUrl = kasEndpoint;
      this.allowedKases = new OriginAllowList(allowedKases || [kasEndpoint], !!ignoreAllowList);
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
    nanoTdfHeader: TypedArray | ArrayBuffer,
    kasRewrapUrl: string,
    magicNumberVersion: TypedArray | ArrayBuffer,
    clientVersion: string
  ): Promise<CryptoKey> {
    if (!this.allowedKases.allows(kasRewrapUrl)) {
      throw new UnsafeUrlError(`request URL ∉ ${this.allowedKases.origins};`, kasRewrapUrl);
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

    const requestBodyStr = JSON.stringify({
      algorithm: DefaultParams.defaultECAlgorithm,
      // nano keyAccess minimum, header is used for nano
      keyAccess: {
        type: Client.KEY_ACCESS_REMOTE,
        url: '',
        protocol: Client.KAS_PROTOCOL,
        header: base64.encodeArrayBuffer(nanoTdfHeader),
      },
      clientPublicKey: await cryptoPublicToPem(ephemeralKeyPair.publicKey),
    });

    const jwtPayload = { requestBody: requestBodyStr };
    const requestBody = {
      signedRequestToken: await reqSignature(jwtPayload, requestSignerKeyPair.privateKey, {
        alg: toJWSAlg(requestSignerKeyPair.publicKey),
      }),
    };

    // Wrapped
    const wrappedKey = await fetchWrappedKey(
      kasRewrapUrl,
      requestBody,
      this.authProvider,
      clientVersion
    );

    // Extract the iv and ciphertext
    const entityWrappedKey = new Uint8Array(base64.decodeArrayBuffer(wrappedKey.entityWrappedKey));
    const ivLength =
      clientVersion == Client.SDK_INITIAL_RELEASE ? Client.INITIAL_RELEASE_IV_SIZE : Client.IV_SIZE;
    const iv = entityWrappedKey.subarray(0, ivLength);
    const encryptedSharedKey = entityWrappedKey.subarray(ivLength);

    let kasPublicKey;
    try {
      // Let us import public key as a cert or public key
      kasPublicKey = await pemToCryptoPublicKey(wrappedKey.sessionPublicKey);
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

    return unwrappedKey;
  }
}
