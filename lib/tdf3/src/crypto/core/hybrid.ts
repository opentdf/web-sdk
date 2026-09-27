import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { isHybridKeyAlgorithm, type PublicKey, type SymmetricKey } from '../declarations.js';
import { ConfigurationError } from '../../../../src/errors.js';
import { HYBRID_PARAMETERS, type HybridParameters } from './hybrid-asn1.js';
import { unwrapHybridKey, wrapSymmetricKey } from './keys.js';

const MLKEM = { 768: ml_kem768, 1024: ml_kem1024 } as const;

/**
 * The combiner of draft-ietf-lamps-pq-composite-kem-14 §3.4:
 * `SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)`. Its 32 bytes are
 * the AES-256 key, with no further KDF, as the OpenTDF platform uses it.
 */
export function hybridCombiner(
  params: HybridParameters,
  mlkemSS: Uint8Array,
  tradSS: Uint8Array,
  tradCT: Uint8Array,
  tradPK: Uint8Array
): Uint8Array {
  const label = new TextEncoder().encode(params.label);
  return sha3_256(Uint8Array.of(...mlkemSS, ...tradSS, ...tradCT, ...tradPK, ...label));
}

/**
 * Encapsulate to a hybrid public key: ECDH against an ephemeral key of the
 * same curve, ML-KEM encapsulation, then the combiner. The ciphertext is the
 * ML-KEM ciphertext followed by the uncompressed ephemeral EC public key.
 */
export async function hybridEncapsulate(
  pk: PublicKey
): Promise<{ ciphertext: Uint8Array; sharedSecret: SymmetricKey }> {
  if (!isHybridKeyAlgorithm(pk.algorithm)) {
    throw new ConfigurationError(`Not a hybrid public key: ${pk.algorithm}`);
  }
  const params = HYBRID_PARAMETERS[pk.algorithm];
  const raw = unwrapHybridKey(pk);
  const mlkemPK = raw.subarray(0, params.mlKemPublicKeySize);
  const tradPK = raw.slice(params.mlKemPublicKeySize);

  const curve = { name: 'ECDH', namedCurve: params.curve };
  const kasKey = await crypto.subtle.importKey('raw', tradPK, curve, false, []);
  const ephemeral = await crypto.subtle.generateKey(curve, true, ['deriveBits']);
  // The ECDH shared secret is the X coordinate: half the point, without its prefix.
  const secretBits = ((params.ecPointSize - 1) / 2) * 8;
  const tradSS = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: kasKey },
      ephemeral.privateKey,
      secretBits
    )
  );
  const tradCT = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));

  const { cipherText: mlkemCT, sharedSecret: mlkemSS } =
    MLKEM[params.mlKemLevel].encapsulate(mlkemPK);
  return {
    ciphertext: Uint8Array.of(...mlkemCT, ...tradCT),
    sharedSecret: wrapSymmetricKey(hybridCombiner(params, mlkemSS, tradSS, tradCT, tradPK)),
  };
}
