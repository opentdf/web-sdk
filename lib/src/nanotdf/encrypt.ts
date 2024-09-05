import NanoTDF from './NanoTDF.js';
import Header from './models/Header.js';
import ResourceLocator from './models/ResourceLocator.js';
import DefaultParams from './models/DefaultParams.js';
import EmbeddedPolicy from './models/Policy/EmbeddedPolicy.js';
import Payload from './models/Payload.js';
import getHkdfSalt from './helpers/getHkdfSalt.js';
import { getBitLength as authTagLengthForCipher } from './models/Ciphers.js';
import { TypedArray } from '../tdf/index.js';
import { GMAC_BINDING_LEN } from './constants.js';
// import { AlgorithmName } from './../nanotdf-crypto/enums.js'

import {
  encrypt as cryptoEncrypt,
  keyAgreement,
  digest,
  exportCryptoKey,
} from '../nanotdf-crypto/index.js';
import { KasPublicKeyInfo } from '../access.js';
import { computeECDSASig, extractRSValuesFromSignature } from '../nanotdf-crypto/ecdsaSignature.js';

/**
 * Encrypt the plain data into nanotdf buffer
 *
 * @param policy Policy that will added to the nanotdf
 * @param kasInfo KAS url and public key data
 * @param ephemeralKeyPair SDK ephemeral key pair to generate symmetric key
 * @param iv
 * @param data The data to be encrypted
 */
export default async function encrypt(
  policy: string,
  kasInfo: KasPublicKeyInfo,
  ephemeralKeyPair: CryptoKeyPair,
  iv: Uint8Array,
  data: string | TypedArray | ArrayBuffer
): Promise<ArrayBuffer> {
  // Generate a symmetric key.
  if (!ephemeralKeyPair.privateKey) {
    throw new Error('incomplete ephemeral key');
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
  if (DefaultParams.ecdsaBinding) {
    console.log('ephemeralKeyPair.privateKey', ephemeralKeyPair.privateKey);

    const curveName = await getCurveNameFromPrivateKey(ephemeralKeyPair.privateKey);

    console.log('curveName', curveName);

    // Export the ECDH private key
    const ecdhPrivateKey = await crypto.subtle.exportKey('pkcs8', ephemeralKeyPair.privateKey);

    // Import the ECDH private key as an ECDSA private key
    const ecdsaPrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      ecdhPrivateKey,
      {
        name: 'ECDSA',
        namedCurve: curveName,
      },
      true,
      ['sign']
    );

    console.log('ecdsaPrivateKey', ecdsaPrivateKey);

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
    throw new Error('incomplete ephemeral key');
  }
  // Create a header
  const pubKeyAsArrayBuffer = await exportCryptoKey(ephemeralKeyPair.publicKey);

  const header = new Header(
    DefaultParams.magicNumberVersion,
    kasResourceLocator,
    DefaultParams.ecdsaBinding,
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

async function getCurveNameFromPrivateKey(privateKey: CryptoKey): Promise<string> {
  // Export the private key
  const keyData = await crypto.subtle.exportKey('jwk', privateKey);

  // The curve name is stored in the 'crv' property of the JWK
  if (!keyData.crv) {
    throw new Error('Curve name is undefined');
  }

  return keyData.crv;
}
