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
import { keyAgreement } from './nanotdf-crypto/index.js';
import { Policy } from './tdf/Policy.js';
import { type TypedArray } from './tdf/TypedArray.js';
import { createAttribute } from './tdf/AttributeObject.js';
import { fetchECKasPubKey } from './access.js';
import { ClientConfig } from './nanotdf/Client.js';
import { ConfigurationError } from './errors.js';

// Define the EncryptOptions type
export type EncryptOptions = {
  ecdsaBinding: boolean;
};

// Define default options
const defaultOptions: EncryptOptions = {
  ecdsaBinding: false,
};

/**
 * NanoTDF SDK Client. Deprecated in favor of OpenTDF.
 *
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

    // TODO: The version number should be fetched from the API
    const version = '0.0.1';
    const kasUrl = nanotdf.header.getKasRewrapUrl();

    // Rewrap key on every request
    const ukey = await this.rewrapKey(
      nanotdf.header.toBuffer(),
      kasUrl,
      nanotdf.header.magicNumberVersion,
      version
    );

    if (!ukey) {
      throw new Error('internal: key rewrap failure');
    }
    // Return decrypt promise
    return decrypt(ukey, nanotdf);
  }

  /**
   * Decrypt ciphertext of the legacy TDF, with the older, smaller i.v. calculation.
   *
   * Pass a base64 string, TypedArray, or ArrayBuffer ciphertext and get a promise which resolves plaintext
   *
   * @param ciphertext Ciphertext to decrypt
   */
  async decryptLegacyTDF(ciphertext: string | TypedArray | ArrayBuffer): Promise<ArrayBuffer> {
    // Parse ciphertext
    const nanotdf = NanoTDF.from(ciphertext, undefined, true);

    const legacyVersion = '0.0.0';
    // Rewrap key on every request
    const key = await this.rewrapKey(
      nanotdf.header.toBuffer(),
      nanotdf.header.getKasRewrapUrl(),
      nanotdf.header.magicNumberVersion,
      legacyVersion
    );

    if (!key) {
      throw new Error('internal: failed unwrap');
    }
    // Return decrypt promise
    return decrypt(key, nanotdf);
  }

  /**
   * Encrypts the given data using the NanoTDF encryption scheme.
   *
   * @param {string | TypedArray | ArrayBuffer} data - The data to be encrypted.
   * @param {EncryptOptions} [options=defaultOptions] - The encryption options (currently unused).
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the encrypted data as an ArrayBuffer.
   * @throws {Error} If the initialization vector is not a number.
   */
  async encrypt(
    data: string | TypedArray | ArrayBuffer,
    options?: EncryptOptions
  ): Promise<ArrayBuffer> {
    // For encrypt always generate the client ephemeralKeyPair
    const ephemeralKeyPair = await this.ephemeralKeyPair;
    const initializationVector = this.iv;

    if (typeof initializationVector !== 'number') {
      throw new ConfigurationError(
        'NanoTDF clients are single use. Please generate a new client and keypair.'
      );
    }
    delete this.iv;

    if (!this.kasPubKey) {
      this.kasPubKey = await fetchECKasPubKey(this.kasUrl);
    }

    // Create a policy for the tdf
    const policy = new Policy();

    // Add data attributes.
    for (const dataAttribute of this.dataAttributes) {
      const attribute = await createAttribute(dataAttribute, this.kasPubKey, this.kasUrl);
      policy.addAttribute(attribute);
    }

    if (this.dissems.length == 0 && this.dataAttributes.length == 0) {
      console.warn(
        'This policy has an empty attributes list and an empty dissemination list. This will allow any entity with a valid Entity Object to access this TDF.'
      );
    }

    // Encrypt the policy.
    const policyObjectAsStr = policy.toJSON();

    // IV is always '1', since the new keypair is generated on encrypt
    // using the same key is fine.
    const lengthAsUint32 = new Uint32Array(1);
    lengthAsUint32[0] = initializationVector;

    const lengthAsUint24 = new Uint8Array(lengthAsUint32.buffer);

    // NOTE: We are only interested in only first 3 bytes.
    const payloadIV = new Uint8Array(12).fill(0);
    payloadIV[9] = lengthAsUint24[2];
    payloadIV[10] = lengthAsUint24[1];
    payloadIV[11] = lengthAsUint24[0];

    const mergedOptions: EncryptOptions = { ...defaultOptions, ...options };
    return encrypt(
      policyObjectAsStr,
      this.kasPubKey,
      ephemeralKeyPair,
      payloadIV,
      data,
      mergedOptions.ecdsaBinding
    );
  }
}

export type DatasetConfig = ClientConfig & {
  maxKeyIterations?: number;
};

/**
 * NanoTDF Dataset SDK Client
 *
 *
 * @example
 * ```
 * import { clientSecretAuthProvider, NanoTDFDatasetClient } from '@opentdf/sdk';
 *
 * const OIDC_ENDPOINT = 'http://localhost:65432/auth/realms/opentdf';
 * const KAS_URL = 'http://localhost:65432/api/kas/';
 *
 * const ciphertext = '...';
 * const client = new NanoTDFDatasetClient({
 *   authProvider: await clientSecretAuthProvider({
 *     clientId: 'tdf-client',
 *     clientSecret: '123-456',
 *     exchange: 'client',
 *     oidcOrigin: OIDC_ENDPOINT,
 *   }),
 *   kasEndpoint: KAS_URL,
 * });
 * const plaintext = client.decrypt(ciphertext);
 * console.log('Plaintext', plaintext);
 * ```
 */
export class NanoTDFDatasetClient extends Client {
  // Total unique IVs(2^24 -1) used for encrypting the nano tdf payloads
  // IV starts from 1 since the 0 IV is reserved for policy encryption
  static readonly NTDF_MAX_KEY_ITERATIONS = 8388606;

  private maxKeyIteration: number;
  private keyIterationCount: number;
  private cachedEphemeralKey?: Uint8Array;
  private unwrappedKey?: CryptoKey;
  private symmetricKey?: CryptoKey;
  private cachedHeader?: Header;
  private ecdsaBinding: boolean;

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
   * @param maxKeyIterations Max iteration to performe without a key rotation
   */
  constructor(opts: DatasetConfig) {
    if (
      opts.maxKeyIterations &&
      opts.maxKeyIterations > NanoTDFDatasetClient.NTDF_MAX_KEY_ITERATIONS
    ) {
      throw new ConfigurationError(
        `key iteration exceeds max iterations(${NanoTDFDatasetClient.NTDF_MAX_KEY_ITERATIONS})`
      );
    }
    super(opts);

    this.maxKeyIteration = opts.maxKeyIterations || NanoTDFDatasetClient.NTDF_MAX_KEY_ITERATIONS;
    this.keyIterationCount = 0;
  }

  /**
   * Encrypt data
   *
   * Pass a string, TypedArray, or ArrayBuffer data and get a promise which resolves ciphertext
   *
   * @param data to decrypt
   */
  async encrypt(
    data: string | TypedArray | ArrayBuffer,
    options?: EncryptOptions
  ): Promise<ArrayBuffer> {
    // Intial encrypt
    if (this.keyIterationCount == 0) {
      const mergedOptions: EncryptOptions = { ...defaultOptions, ...options };
      this.ecdsaBinding = mergedOptions.ecdsaBinding;
      // For encrypt always generate the client ephemeralKeyPair
      const ephemeralKeyPair = await this.ephemeralKeyPair;

      if (!this.kasPubKey) {
        this.kasPubKey = await fetchECKasPubKey(this.kasUrl);
      }

      // Create a policy for the tdf
      const policy = new Policy();

      // Add data attributes.
      for (const dataAttribute of this.dataAttributes) {
        const attribute = await createAttribute(dataAttribute, this.kasPubKey, this.kasUrl);
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
        await this.kasPubKey.key,
        await getHkdfSalt(DefaultParams.magicNumberVersion)
      );

      const nanoTDFBuffer = await encrypt(
        policyObjectAsStr,
        this.kasPubKey,
        ephemeralKeyPair,
        ivVector,
        data,
        this.ecdsaBinding
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
      throw new ConfigurationError('invalid dataset client: empty nanoTDF header');
    }
    if (!this.symmetricKey) {
      throw new ConfigurationError('invalid dataset client: empty dek');
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

    if (!this.cachedEphemeralKey) {
      // First decrypt
      return this.rewrapAndDecrypt(nanotdf);
    }

    // Other encrypts
    if (this.cachedEphemeralKey.toString() == nanotdf.header.ephemeralPublicKey.toString()) {
      const ukey = this.unwrappedKey;
      if (!ukey) {
        // These should have thrown already.
        throw new Error('internal: key rewrap failure');
      }
      // Return decrypt promise
      return decrypt(ukey, nanotdf);
    } else {
      return this.rewrapAndDecrypt(nanotdf);
    }
  }

  async rewrapAndDecrypt(nanotdf: NanoTDF) {
    // TODO: The version number should be fetched from the API
    const version = '0.0.1';
    // Rewrap key on every request
    const ukey = await this.rewrapKey(
      nanotdf.header.toBuffer(),
      nanotdf.header.getKasRewrapUrl(),
      nanotdf.header.magicNumberVersion,
      version
    );
    if (!ukey) {
      // These should have thrown already.
      throw new Error('internal: key rewrap failure');
    }

    this.cachedEphemeralKey = nanotdf.header.ephemeralPublicKey;
    this.unwrappedKey = ukey;

    // Return decrypt promise
    return decrypt(ukey, nanotdf);
  }

  generateIV(): Uint8Array {
    const iv = this.iv;
    if (iv === undefined) {
      // iv has passed the maximum iteration count for this dek
      throw new ConfigurationError('dataset full');
    }
    // assert iv ∈ ℤ ∩ (0, 2^24)
    if (!Number.isInteger(iv) || iv <= 0 || 0xff_ffff < iv) {
      // Something has fiddled with the iv outside of the expected behavior
      // could indicate a race condition, e.g. if two workers or handlers are
      // processing the file at once, for example.
      throw new Error('internal: invalid state');
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
    if (iv == 0xff_ffff) {
      delete this.iv;
    } else {
      this.iv = iv + 1;
    }

    return ivVector;
  }
}
