import NanoTDF from './NanoTDF.js';
import Header from './models/Header.js';
import ResourceLocator from './models/ResourceLocator.js';
import DefaultParams from './models/DefaultParams.js';
import EmbeddedPolicy from './models/Policy/EmbeddedPolicy.js';
import Payload from './models/Payload.js';
import getHkdfSalt from './helpers/getHkdfSalt.js';
import { getBitLength as authTagLengthForCipher } from './models/Ciphers.js';
import { lengthOfBinding } from './helpers/calculateByCipher.js';
import { TypedArray } from '../tdf/index.js';

import {
  encrypt as cryptoEncrypt,
  keyAgreement,
  extractPublicFromCertToCrypto,
  digest,
  exportCryptoKey,
} from '../nanotdf-crypto/index.js';

/**
 * Encrypt the plain data into nanotdf buffer
 *
 * @param policy Policy that will added to the nanotdf
 * @param kasPubCrtAsPem KAS public crt in pem format
 * @param kasUrl KAS url as string
 * @param ephemeralKeyPair SDK ephemeral key pair to generate symmetric key
 * @param data The data to be encrypted
 */
export default async function encrypt(
  policy: string,
  kasPubCrtAsPem: string,
  kasUrl: string,
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
    // Get session public key as crypto key
    await extractPublicFromCertToCrypto(kasPubCrtAsPem),
    // Get the hkdf salt params
    await getHkdfSalt(DefaultParams.magicNumberVersion)
  );

  // Construct the kas locator
  const kasResourceLocator = ResourceLocator.parse(kasUrl);

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

  // Enable - once ecdsaBinding is true
  // if (!DefaultParams.ecdsaBinding) {
  //   throw new Error("ECDSA binding should enable by default.");
  // }

  // // Calculate the policy binding.
  // const policyBinding = await calculateSignature(this.ephemeralKeyPair.privateKey, new Uint8Array(encryptedPolicy));
  // console.log("Length of the policyBinding " + policyBinding.byteLength);

  // // Create embedded policy
  // const embeddedPolicy = new EmbeddedPolicy(DefaultParams.policyType,
  //   new Uint8Array(policyBinding),
  //   new Uint8Array(encryptedPolicy)
  // );

  // Calculate the policy binding.
  const lengthOfPolicyBinding = lengthOfBinding(
    DefaultParams.ecdsaBinding,
    DefaultParams.ephemeralCurveName
  );

  const policyBinding = await digest('SHA-256', new Uint8Array(encryptedPolicy));

  // Create embedded policy
  const embeddedPolicy = new EmbeddedPolicy(
    DefaultParams.policyType,
    new Uint8Array(policyBinding.slice(-lengthOfPolicyBinding)),
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
