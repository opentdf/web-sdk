import NanoTDF from './NanoTDF.js';
import Header from './models/Header.js';
import ResourceLocator from './models/ResourceLocator.js';
import DefaultParams from './models/DefaultParams.js';
import EmbeddedPolicy from './models/Policy/EmbeddedPolicy.js';
import Payload from './models/Payload.js';
import getHkdfSalt from './helpers/getHkdfSalt.js';
import { getBitLength as authTagLengthForCipher } from './models/Ciphers.js';
import { TypedArray } from '../tdf/TypedArray.js';
import { GMAC_BINDING_LEN } from './constants.js';
import { AlgorithmName, KeyFormat, KeyUsageType } from './../nanotdf-crypto/enums.js';

import {
  encrypt as cryptoEncrypt,
  keyAgreement,
  digest,
  exportCryptoKey,
} from '../nanotdf-crypto/index.js';
import { KasPublicKeyInfo } from '../access.js';
import { computeECDSASig, extractRSValuesFromSignature } from '../nanotdf-crypto/ecdsaSignature.js';
import { ConfigurationError } from '../errors.js';

/**
 * Encrypt the plain data into nanotdf buffer
 *
 * @param policy Policy that will added to the nanotdf
 * @param kasInfo KAS url and public key data
 * @param ephemeralKeyPair SDK ephemeral key pair to generate symmetric key
 * @param iv
 * @param data The data to be encrypted
 * @param ecdsaBinding Flag to enable ECDSA binding
 */
export default async function encrypt(
  policy: string,
  kasInfo: KasPublicKeyInfo,
  ephemeralKeyPair: CryptoKeyPair,
  iv: Uint8Array,
  data: string | TypedArray | ArrayBuffer,
  ecdsaBinding: boolean = DefaultParams.ecdsaBinding
): Promise<ArrayBuffer> {
  // Generate a symmetric key.
  if (!ephemeralKeyPair.privateKey) {
    throw new ConfigurationError('incomplete ephemeral key');
  }
  const symmetricKey = await keyAgreement(
    ephemeralKeyPair.privateKey,
    await kasInfo.key,
    // Get the hkdf salt params
    await getHkdfSalt(DefaultParams.magicNumberVersion)
  );

  // Construct the kas locator
  const kasResourceLocator = ResourceLocator.fromURL(kasInfo.url, kasInfo.kid);

  // Auth tag length for policy and payload
  const authTagLengthInBytes = authTagLengthForCipher(DefaultParams.symmetricCipher) / 8;

  // Encrypt the policy
  const policyIV = new Uint8Array(iv.length).fill(0);
  const policyAsBuffer = new TextEncoder().encode(policy);
  const encryptedPolicy = await cryptoEncrypt(
    symmetricKey,
    policyAsBuffer,
    policyIV,
    authTagLengthInBytes * 8
  );

  let policyBinding: Uint8Array;

  // Calculate the policy binding.
  if (ecdsaBinding) {
    const curveName = await getCurveNameFromPrivateKey(ephemeralKeyPair.privateKey);
    const ecdsaPrivateKey = await convertECDHToECDSA(ephemeralKeyPair.privateKey, curveName);
    const ecdsaSignature = await computeECDSASig(ecdsaPrivateKey, new Uint8Array(encryptedPolicy));
    const { r, s } = extractRSValuesFromSignature(new Uint8Array(ecdsaSignature));

    const rLength = r.length;
    const sLength = s.length;

    policyBinding = new Uint8Array(1 + rLength + 1 + sLength);

    // Set the lengths and values of r and s in policyBinding
    policyBinding[0] = rLength;
    policyBinding.set(r, 1);
    policyBinding[1 + rLength] = sLength;
    policyBinding.set(s, 1 + rLength + 1);
  } else {
    const signature = await digest('SHA-256', new Uint8Array(encryptedPolicy));
    policyBinding = new Uint8Array(signature.slice(-GMAC_BINDING_LEN));
  }

  // Create embedded policy
  const embeddedPolicy = new EmbeddedPolicy(
    DefaultParams.policyType,
    policyBinding,
    new Uint8Array(encryptedPolicy)
  );

  if (!ephemeralKeyPair.publicKey) {
    throw new ConfigurationError('incomplete ephemeral key');
  }
  // Create a header
  const pubKeyAsArrayBuffer = await exportCryptoKey(ephemeralKeyPair.publicKey);

  const header = new Header(
    DefaultParams.magicNumberVersion,
    kasResourceLocator,
    ecdsaBinding,
    DefaultParams.signatureCurveName,
    DefaultParams.signature,
    DefaultParams.signatureCurveName,
    DefaultParams.symmetricCipher,
    embeddedPolicy,
    new Uint8Array(pubKeyAsArrayBuffer)
  );

  // Encrypt the payload
  let payloadAsBuffer;
  if (typeof data === 'string') {
    payloadAsBuffer = new TextEncoder().encode(data);
  } else {
    payloadAsBuffer = data;
  }

  const encryptedPayload = await cryptoEncrypt(
    symmetricKey,
    new Uint8Array(payloadAsBuffer),
    iv,
    authTagLengthInBytes * 8
  );

  // Create payload
  const payload = new Payload(
    iv.slice(-3),
    new Uint8Array(encryptedPayload.slice(0, -authTagLengthInBytes)),
    new Uint8Array(encryptedPayload.slice(-authTagLengthInBytes))
  );

  // Create a nanotdf.
  const nanoTDF = new NanoTDF(header, payload);
  return nanoTDF.toBuffer();
}

/**
 * Retrieves the curve name from a given ECDH private key.
 *
 * This function exports the provided ECDH private key in JWK format and extracts
 * the curve name from the 'crv' property of the JWK.
 *
 * @param {CryptoKey} privateKey - The ECDH private key from which to retrieve the curve name.
 * @returns {Promise<string>} - A promise that resolves to the curve name.
 *
 * @throws {Error} - Throws an error if the curve name is undefined.
 *
 */
async function getCurveNameFromPrivateKey(privateKey: CryptoKey): Promise<string> {
  // Export the private key
  const keyData = await crypto.subtle.exportKey('jwk', privateKey);

  // The curve name is stored in the 'crv' property of the JWK
  if (!keyData.crv) {
    throw new ConfigurationError('curve name is undefined (bad private key)');
  }

  return keyData.crv;
}

/**
 * Converts an ECDH private key to an ECDSA private key.
 *
 * This function exports the given ECDH private key in PKCS#8 format and then
 * imports it as an ECDSA private key using the specified curve name.
 *
 * @param {CryptoKey} key - The ECDH private key to be converted.
 * @param {string} curveName - The name of the elliptic curve to be used for the ECDSA key.
 * @returns {Promise<CryptoKey>} - A promise that resolves to the converted ECDSA private key.
 *
 * @throws {Error} - Throws an error if the key export or import fails.
 */
async function convertECDHToECDSA(key: CryptoKey, curveName: string): Promise<CryptoKey> {
  // Export the ECDH private key
  const ecdhPrivateKey = await crypto.subtle.exportKey('pkcs8', key);

  // Import the ECDH private key as an ECDSA private key
  const ecdsaPrivateKey = await crypto.subtle.importKey(
    KeyFormat.Pkcs8,
    ecdhPrivateKey,
    {
      name: AlgorithmName.ECDSA,
      namedCurve: curveName,
    },
    true,
    [KeyUsageType.Sign]
  );

  return ecdsaPrivateKey;
}
