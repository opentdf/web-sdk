import { Client, NanoTDF, encrypt, decrypt } from './nanotdf/index.js';
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
    if (!ukey) throw new Error();
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

    await this.fetchOIDCToken();

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

export * as AuthProviders from './nanotdf/Client.js';
