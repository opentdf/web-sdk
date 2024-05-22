import { type TypedArray } from '../tdf/index.js';
import * as base64 from '../encodings/base64.js';
import {
  decrypt,
  enums as cryptoEnums,
  generateKeyPair,
  keyAgreement,
} from '../nanotdf-crypto/index.js';
import getHkdfSalt from './helpers/getHkdfSalt.js';
import DefaultParams from './models/DefaultParams.js';
import { fetchWrappedKey } from '../kas.js';
import { AuthProvider, isAuthProvider, reqSignature } from '../auth/providers.js';
import { cryptoPublicToPem } from '../keyport/pem.js';
import { safeUrlCheck, validateSecureUrl } from '../urltils.js';
import { pemPublicToCrypto } from '../keyport/raw.js';

const { KeyUsageType, AlgorithmName, NamedCurve } = cryptoEnums;

export interface ClientConfig {
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
  throw new Error(`Unsupported key algorithm ${JSON.stringify(algorithm)}`);
}

async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair();
  if (!privateKey || !publicKey) {
    throw Error('Key pair generation failed');
  }
  return { publicKey, privateKey };
}

async function generateSignerKeyPair(): Promise<CryptoKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair({
    type: AlgorithmName.ECDSA,
    curve: NamedCurve.P256,
    keyUsages: [KeyUsageType.Sign, KeyUsageType.Verify],
    isExtractable: true,
  });
  if (!privateKey || !publicKey) {
    throw Error('Signer key pair generation failed');
  }
  return { publicKey, privateKey };
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
 * import { Client, clientAuthProvider, decrypt, encrypt } from '@opentdf/client/nanotdf`
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

  allowedKases: string[];
  /*
    These variables are expected to be either assigned during initialization or within the methods.
    This is needed as the flow is very specific. Errors should be thrown if the necessary step is not completed.
  */
  kasUrl: string;
  kasPubKey?: CryptoKey;
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
    if (isAuthProvider(optsOrOldAuthProvider)) {
      this.authProvider = optsOrOldAuthProvider;
      if (!kasUrl) {
        throw new Error('please specify kasEndpoint');
      }
      // TODO Disallow http KAS. For now just log as error
      validateSecureUrl(kasUrl);
      this.kasUrl = kasUrl;
      this.allowedKases = [kasUrl];
      this.dpopEnabled = dpopEnabled;

      if (ephemeralKeyPair) {
        this.ephemeralKeyPair = Promise.resolve(ephemeralKeyPair);
      } else {
        this.ephemeralKeyPair = generateEphemeralKeyPair();
      }
      this.iv = 1;
    } else {
      const { authProvider, dpopEnabled, dpopKeys, ephemeralKeyPair, kasEndpoint } =
        optsOrOldAuthProvider;
      this.authProvider = authProvider;
      // TODO Disallow http KAS. For now just log as error
      validateSecureUrl(kasEndpoint);
      this.kasUrl = kasEndpoint;
      this.allowedKases = [kasEndpoint];
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
   * Explicitly get a new Entity Object using the supplied EntityAttributeService.
   *
   * This method is expected to be called at least once per encrypt/decrypt cycle. If the entityObject is expired then
   * this will need to be called again.
   *
   * @security the ephemeralKeyPair must be set in the constructor if desired to use here. If this is wished to be changed
   * then a new client should be initialized.
   * @performance key pair is generated when the entity object is fetched IFF the ephemeralKeyPair is not set. This will
   * either be set on the first call or passed in the constructor.
   */
  async fetchOIDCToken(): Promise<void> {
    const signer = await this.requestSignerKeyPair;
    if (!signer) {
      throw new Error('Unexpected state');
    }

    await this.authProvider.updateClientPublicKey(signer);
  }

  /**
   * Rewrap key
   *
   * @important the `fetchEntityObject` method must be called prior to
   * @param nanoTdfHeader the full header for the nanotdf
   * @param kasRewrapUrl key access server's rewrap endpoint
   * @param magicNumberVersion nanotdf container version
   * @param clientVersion version of the client, as SemVer
   * @param authTagLength number of bytes to keep in the authTag
   */
  async rewrapKey(
    nanoTdfHeader: TypedArray | ArrayBuffer,
    kasRewrapUrl: string,
    magicNumberVersion: TypedArray | ArrayBuffer,
    clientVersion: string,
    authTagLength: number
  ): Promise<CryptoKey> {
    safeUrlCheck(this.allowedKases, kasRewrapUrl);

    // Ensure the ephemeral key pair has been set or generated (see createOidcServiceProvider)
    await this.fetchOIDCToken();
    const ephemeralKeyPair = await this.ephemeralKeyPair;
    const requestSignerKeyPair = await this.requestSignerKeyPair;

    // Ensure the ephemeral key pair has been set or generated (see fetchEntityObject)
    if (!ephemeralKeyPair?.privateKey) {
      throw new Error('Ephemeral key has not been set or generated');
    }

    if (!requestSignerKeyPair?.privateKey) {
      throw new Error('Signer key has not been set or generated');
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
    const kasPublicKey = await pemPublicToCrypto(wrappedKey.sessionPublicKey);
    const hkdfSalt = await getHkdfSalt(magicNumberVersion);
    const { privateKey } = await this.ephemeralKeyPair;

    // Get the unwrapping key
    const unwrappingKey = await keyAgreement(
      // Ephemeral private key
      privateKey,
      kasPublicKey,
      hkdfSalt
    );

    // console.error("mine public", (await this.ephemeralKeyPair).publicKey);
    // console.error("wrapping with (mine public) x yourPublic / salt", await cryptoPublicToPem((await this.ephemeralKeyPair).publicKey), await cryptoPublicToPem(kasPublicKey), hkdfSalt);
    // console.error("derived aes key", unwrappingKey, await crypto.subtle.exportKey("jwk", unwrappingKey));

    const decryptedKey = await decrypt(unwrappingKey, encryptedSharedKey, iv, authTagLength);

    const unwrappedKey = await crypto.subtle.importKey(
      'raw',
      decryptedKey,
      'AES-GCM',
      // @security This allows the key to be used in `exportKey` and `wrapKey`
      // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
      // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey
      true,
      // Want to use the key to encrypt and decrypt. Signing key will be used later.
      ['encrypt', 'decrypt'],
    );

    return unwrappedKey;
  }
}
