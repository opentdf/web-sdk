// Constants only, with no imports, so that sizing code (`utils/scale-limits`)
// can depend on them without pulling in the encryptor and, through it, the
// `utils` barrel that imports `scale-limits` back.

export const AES_GCM_IV_LENGTH = 12;
export const AES_GCM_TAG_LENGTH = 16;

/**
 * The largest invocation limit an encryptor may declare. SP 800-38D 8.3 caps
 * keys using RBG-based (8.2.2) IVs at 2^32 invocations; the deterministic
 * construction here reaches the same number through its 32-bit invocation
 * field. RBG encryptors should declare less (the DSPX-4492 ADR recommends at
 * most 2^26), but none may declare more.
 */
export const MAX_AES_GCM_INVOCATIONS = 2 ** 32;
