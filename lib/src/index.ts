import {
  Client,
  NanoTDF,
  Header,
  encrypt,
  decrypt,
  encryptDataset,
  getHkdfSalt,
  DefaultParams,
} from './nanotdf/index.js';
import { keyAgreement, extractPublicFromCertToCrypto } from './nanotdf-crypto/index.js';
import { TypedArray, createAttribute, Policy } from './tdf/index.js';

/**
 * NanoTDF SDK Client
 *
 * @example
 *  import NanoTDFClient from '@opentdf/client';
 *
 *  const OIDC_ENDPOINT = 'http://localhost:65432/keycloak/';
 *  const KAS_URL = 'http://localhost:65432/kas';
 *
 *  const ciphertext = '...';
 *  const client = new NanoTDFClient(
 *    {
 *      clientId: 'tdf-client',
 *      clientSecret: '123-456',
 *      organizationName: 'tdf',
 *      oidcOrigin: OIDC_ENDPOINT,
 *    },
 *    KAS_URL
 *  );
 *  client.decrypt(ciphertext)
 *    .then(plaintext => {
 *      console.log('Plaintext', plaintext);
 *    })
 *    .catch(err => {
 *      console.error('Some error occurred', err);
 *    })
 */
export class NanoTDFClient extends Client {
  /**
   * Decrypt ciphertext
   *
   * Pass a base64 string, TypedArray, or ArrayBuffer ciphertext and get a promise which resolves plaintext
   *
   * @param ciphertext Ciphertext to decrypt
   */
  async decrypt(ciphertext: string | TypedArray | ArrayBuffer): Promise<ArrayBuffer> {
    // Parse ciphertext
    const nanotdf = NanoTDF.from(ciphertext);

    await this.fetchOIDCToken();

    // TODO: The version number should be fetched from the API
    const version = '0.0.1';
    // Rewrap key on every request
    await this.rewrapKey(
      nanotdf.header.toBuffer(),
      nanotdf.header.getKasRewrapUrl(),
      nanotdf.header.magicNumberVersion,
      version,
      nanotdf.header.authTagLength
    );

    const ukey = this.unwrappedKey;
    if (!ukey) {
      throw new Error('Key rewrap failure');
    }
    // Return decrypt promise
    return decrypt(ukey, nanotdf);
  }

  /**
   * Decrypt ciphertext of the legacy TDF
   *
   * Pass a base64 string, TypedArray, or ArrayBuffer ciphertext and get a promise which resolves plaintext
   *
   * @param ciphertext Ciphertext to decrypt
   */
  async decryptLegacyTDF(ciphertext: string | TypedArray | ArrayBuffer): Promise<ArrayBuffer> {
    // Parse ciphertext
    const nanotdf = NanoTDF.from(ciphertext, undefined, true);

    await this.fetchOIDCToken();

    const legacyVersion = '0.0.0';
    // Rewrap key on every request
    await this.rewrapKey(
      nanotdf.header.toBuffer(),
      nanotdf.header.getKasRewrapUrl(),
      nanotdf.header.magicNumberVersion,
      legacyVersion,
      nanotdf.header.authTagLength
    );

    const key = this.unwrappedKey;
    if (!key) {
      throw new Error('Failed unwrap');
    }
    // Return decrypt promise
    return decrypt(key, nanotdf);
  }

  /**
   * Encrypt data
   *
   * Pass a string, TypedArray, or ArrayBuffer data and get a promise which resolves ciphertext
   *
   * @param data to decrypt
   */
  async encrypt(data: string | TypedArray | ArrayBuffer): Promise<ArrayBuffer> {
    // For encrypt always generate the client ephemeralKeyPair
    await this.generateEphemeralKeyPair();

    if (!this.kasPubKey) {
      const kasPubKeyResponse = await fetch(`${this.kasUrl}/kas_public_key?algorithm=ec:secp256r1`);
      this.kasPubKey = await kasPubKeyResponse.json();
    }

    // Create a policy for the tdf
    const policy = new Policy();

    // Add data attributes.
    for (const dataAttribute of this.dataAttributes) {
      const attribute = createAttribute(dataAttribute, this.kasPubKey, this.kasUrl);
      policy.addAttribute(attribute);
    }

    if (this.dissems.length == 0 || this.dataAttributes.length == 0) {
      console.warn(
        'This policy has an empty attributes list and an empty dissemination list. This will allow any entity with a valid Entity Object to access this TDF.'
      );
    }

    // Encrypt the policy.
    const policyObjectAsStr = policy.toJSON();

    // IV is always '1', since the new keypair is generated on encrypt
    // using the same key is fine.
    const lengthAsUint32 = new Uint32Array(1);
    lengthAsUint32[0] = this.iv!;
    delete this.iv;

    const lengthAsUint24 = new Uint8Array(lengthAsUint32.buffer);

    // NOTE: We are only interested in only first 3 bytes.
    const payloadIV = new Uint8Array(12).fill(0);
    payloadIV[9] = lengthAsUint24[2];
    payloadIV[10] = lengthAsUint24[1];
    payloadIV[11] = lengthAsUint24[0];

    return encrypt(
      policyObjectAsStr,
      this.kasPubKey,
      this.kasUrl,
      this.ephemeralKeyPair!,
      payloadIV,
      data
    );
  }
}

/**
 * NanoTDF Dataset SDK Client
 *
 *
 * @example
 *  import NanoTDFDatasetClient from 'nanotdf-sdk';
 *
 *  const OIDC_ENDPOINT = 'http://localhost:65432/keycloak/';
 *  const KAS_URL = 'http://localhost:65432/kas';
 *
 *  const ciphertext = '...';
 *  const client = new NanoTDFDatasetClient.default(
 *    {
 *      clientId: 'tdf-client',
 *      clientSecret: '123-456',
 *      organizationName: 'tdf',
 *      exchange: 'client',
 *      oidcOrigin: OIDC_ENDPOINT,
 *    },
 *    KAS_URL
 *  );
 *  client.decrypt(ciphertext)
 *    .then(plaintext => {
 *      console.log('Plaintext', plaintext);
 *    })
 *    .catch(err => {
 *      console.error('Some error occurred', err);
 *    })
 */
export class NanoTDFDatasetClient extends Client {
  // Total unique IVs(2^24 -1) used for encrypting the nano tdf payloads
  // IV starts from 1 since the 0 IV is reserved for policy encryption
  static readonly NTDF_MAX_KEY_ITERATIONS = 8388606;

  private maxKeyIteration: number;
  private keyIterationCount: number;
  private cachedEphemmeralKey?: Uint8Array;
  private symmetricKey?: CryptoKey;
  private cachedHeader?: Header;

  /**
   * Create new NanoTDF Client
   *
   * The Ephemeral Key Pair can either be provided or will be generate when fetching the entity object. Once set it
   * cannot be changed. If a new ephemeral key is desired it a new client should be initialized.
   * There is no performance impact for creating a new client IFF the ephemeral key pair is provided.
   *
   * @param clientConfig OIDC client credentials
   * @param kasUrl Key access service URL
   * @param ephemeralKeyPair (optional) ephemeral key pair to use
   * @param clientPubKey Client identification
   */

  /**
   * Create new NanoTDF Dataset Client
   *
   * The Ephemeral Key Pair can either be provided or will be generate when fetching the entity object. Once set it
   * cannot be changed. If a new ephemeral key is desired it a new client should be initialized.
   * There is no performance impact for creating a new client IFF the ephemeral key pair is provided.
   *
   * @param clientConfig OIDC client credentials
   * @param kasUrl Key access service URL
   * @param ephemeralKeyPair (optional) ephemeral key pair to use
   * @param clientPubKey Client identification
   * @param maxKeyIterations Max iteration to performe without a key rotation
   */
  constructor(
    clientConfig: any, // Can contain: organizationName, clientId, clientSecret, oidcRefreshToken, oidcOrigin, externalJwt
    kasUrl: string,
    ephemeralKeyPair?: CryptoKeyPair,
    clientPubKey?: string,
    maxKeyIterations: number = NanoTDFDatasetClient.NTDF_MAX_KEY_ITERATIONS
  ) {
    if (maxKeyIterations > NanoTDFDatasetClient.NTDF_MAX_KEY_ITERATIONS) {
      throw new Error('Key iteration exceeds max iterations(8388606)');
    }

    super(clientConfig, kasUrl);

    this.maxKeyIteration = maxKeyIterations;
    this.keyIterationCount = 0;
  }

  /**
   * Encrypt data
   *
   * Pass a string, TypedArray, or ArrayBuffer data and get a promise which resolves ciphertext
   *
   * @param data to decrypt
   */
  async encrypt(data: string | TypedArray | ArrayBuffer): Promise<ArrayBuffer> {
    // Intial encrypt
    if (this.keyIterationCount == 0) {
      // For encrypt always generate the client ephemeralKeyPair
      const ephemeralKeyPair = await this.generateEphemeralKeyPair();

      if (!this.kasPubKey) {
        const kasPubKeyResponse = await fetch(
          `${this.kasUrl}/kas_public_key?algorithm=ec:secp256r1`
        );
        this.kasPubKey = await kasPubKeyResponse.json();
      }

      // Create a policy for the tdf
      const policy = new Policy();

      // Add data attributes.
      for (const dataAttribute of this.dataAttributes) {
        const attribute = createAttribute(dataAttribute, this.kasPubKey, this.kasUrl);
        policy.addAttribute(attribute);
      }

      if (this.dissems.length == 0 || this.dataAttributes.length == 0) {
        console.warn(
          'This policy has an empty attributes list and an empty dissemination list. This will allow any entity with a valid Entity Object to access this TDF.'
        );
      }

      // Encrypt the policy.
      const policyObjectAsStr = policy.toJSON();

      const ivVector = this.generateIV();

      // Generate a symmetric key.
      this.symmetricKey = await keyAgreement(
        ephemeralKeyPair.privateKey,
        await extractPublicFromCertToCrypto(this.kasPubKey),
        await getHkdfSalt(DefaultParams.magicNumberVersion)
      );

      const nanoTDFBuffer = await encrypt(
        policyObjectAsStr,
        this.kasPubKey,
        this.kasUrl,
        ephemeralKeyPair,
        ivVector,
        data
      );

      // Cache the header and increment the key iteration
      if (!this.cachedHeader) {
        const nanoTDF = NanoTDF.from(nanoTDFBuffer);
        this.cachedHeader = nanoTDF.header;
      }

      this.keyIterationCount += 1;

      return nanoTDFBuffer;
    }

    this.keyIterationCount += 1;

    if (!this.cachedHeader) {
      throw new Error('NanoTDF dataset header should have been assgined');
    }

    if (!this.symmetricKey) {
      throw new Error('NanoTDF dataset payload key is not set');
    }

    this.keyIterationCount += 1;
    if (this.keyIterationCount == this.maxKeyIteration) {
      // reset the key iteration
      this.keyIterationCount = 0;
    }

    const ivVector = this.generateIV();

    return encryptDataset(this.symmetricKey, this.cachedHeader, ivVector, data);
  }

  /**
   * Decrypt ciphertext
   *
   * Pass a base64 string, TypedArray, or ArrayBuffer ciphertext and get a promise which resolves plaintext
   *
   * @param ciphertext Ciphertext to decrypt
   */
  async decrypt(ciphertext: string | TypedArray | ArrayBuffer): Promise<ArrayBuffer> {
    // Parse ciphertext
    const nanotdf = NanoTDF.from(ciphertext);

    if (!this.cachedEphemmeralKey) {
      // First decrypt
      return this.rewrapAndDecrypt(nanotdf);
    }

    // Other encrypts
    if (this.cachedEphemmeralKey.toString() == nanotdf.header.ephemeralPublicKey.toString()) {
      const ukey = this.unwrappedKey;
      if (!ukey) {
        throw new Error('Key rewrap failure');
      }
      // Return decrypt promise
      return decrypt(ukey, nanotdf);
    } else {
      return this.rewrapAndDecrypt(nanotdf);
    }
  }

  async rewrapAndDecrypt(nanotdf: NanoTDF) {
    // TODO: The version number should be fetched from the API
    await this.fetchOIDCToken();

    const version = '0.0.1';
    // Rewrap key on every request
    await this.rewrapKey(
      nanotdf.header.toBuffer(),
      nanotdf.header.getKasRewrapUrl(),
      nanotdf.header.magicNumberVersion,
      version,
      nanotdf.header.authTagLength
    );
    const ukey = this.unwrappedKey;
    if (!ukey) {
      throw new Error('Key rewrap failure');
    }

    this.cachedEphemmeralKey = nanotdf.header.ephemeralPublicKey;

    // Return decrypt promise
    return decrypt(ukey, nanotdf);
  }

  generateIV(): Uint8Array {
    const iv = this.iv;
    if (iv === undefined) {
      throw new Error('Dataset full');
    }

    const lengthAsUint32 = new Uint32Array(1);
    lengthAsUint32[0] = iv;

    const lengthAsUint24 = new Uint8Array(lengthAsUint32.buffer);

    // NOTE: We are only interested in only first 3 bytes.
    const ivVector = new Uint8Array(Client.IV_SIZE).fill(0);
    ivVector[9] = lengthAsUint24[2];
    ivVector[10] = lengthAsUint24[1];
    ivVector[11] = lengthAsUint24[0];

    // Increment the IV
    if (iv == 0xfff) {
      delete this.iv;
    } else {
      this.iv = iv + 1;
    }

    return ivVector;
  }
}

export * as AuthProviders from './nanotdf/Client.js';
