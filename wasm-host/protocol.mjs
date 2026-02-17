// protocol.mjs — SharedArrayBuffer layout and constants shared between
// crypto-handler.mjs (main thread) and worker.mjs (Worker thread).
//
// Layout:
//   Control region (32 bytes):
//     [0]   Int32   status: IDLE=0, REQUEST=1, RESPONSE=2, ERROR=3
//     [4]   Uint32  operation ID
//     [8]   Uint32  input1 length (e.g., key / pubPEM)
//     [12]  Uint32  input2 length (e.g., plaintext / ciphertext)
//     [16]  Uint32  scalar parameter (e.g., random byte count, RSA bits)
//     [20]  Uint32  result length (written by main thread)
//     [24]  Uint32  extra value (e.g., privPEM length for keypair gen)
//     [28]  reserved
//
//   Data region (2 MB, starts at offset 32):
//     [32 .. 32+1MB)   Input area:  input1 || input2 (written by Worker)
//     [32+1MB .. end)   Output area: result (written by main thread)

// Status values
export const STATUS_IDLE = 0;
export const STATUS_REQUEST = 1;
export const STATUS_RESPONSE = 2;
export const STATUS_ERROR = 3;

// Control region byte offsets (Int32Array index = offset / 4)
export const OFF_STATUS = 0;
export const OFF_OP_ID = 4;
export const OFF_INPUT1_LEN = 8;
export const OFF_INPUT2_LEN = 12;
export const OFF_SCALAR = 16;
export const OFF_RESULT_LEN = 20;
export const OFF_EXTRA = 24;

// Sizes
export const CTRL_BYTES = 32;
export const DATA_SIZE = 2 * 1024 * 1024;
export const TOTAL_SAB_SIZE = CTRL_BYTES + DATA_SIZE;

// Data region offsets (absolute, from start of SAB)
export const INPUT_OFFSET = CTRL_BYTES; // 32
export const OUTPUT_OFFSET = CTRL_BYTES + 1024 * 1024; // 32 + 1MB

// Operation IDs
export const OP_RANDOM_BYTES = 0;
export const OP_AES_GCM_ENCRYPT = 1;
export const OP_AES_GCM_DECRYPT = 2;
export const OP_HMAC_SHA256 = 3;
export const OP_RSA_OAEP_SHA1_ENCRYPT = 4;
export const OP_RSA_OAEP_SHA1_DECRYPT = 5;
export const OP_RSA_GENERATE_KEYPAIR = 6;

// Error sentinel (matches Go host convention: 0xFFFFFFFF)
export const ERR_SENTINEL = 0xFFFFFFFF;
