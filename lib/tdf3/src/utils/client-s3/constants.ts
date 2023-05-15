export const AMZ_DATE_QUERY_PARAM = "X-Amz-Date";
export const TOKEN_QUERY_PARAM = "X-Amz-Security-Token";
export const AUTH_HEADER = "authorization";
export const AMZ_DATE_HEADER = AMZ_DATE_QUERY_PARAM.toLowerCase();
export const DATE_HEADER = "date";
export const SHA256_HEADER = "x-amz-content-sha256";
export const TOKEN_HEADER = TOKEN_QUERY_PARAM.toLowerCase();

export const ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256";

export const SHA_256_HASH: { name: "SHA-256" } = { name: "SHA-256" };

export const SHA_256_HMAC_ALGO: { name: "HMAC"; hash: { name: "SHA-256" } } = {
  name: "HMAC",
  hash: SHA_256_HASH
};

export const EMPTY_DATA_SHA_256 = new Uint8Array([
  227,
  176,
  196,
  66,
  152,
  252,
  28,
  20,
  154,
  251,
  244,
  200,
  153,
  111,
  185,
  36,
  39,
  174,
  65,
  228,
  100,
  155,
  147,
  76,
  164,
  149,
  153,
  27,
  120,
  82,
  184,
  85
]);

export const ALWAYS_UNSIGNABLE_HEADERS = {
  authorization: true,
  "cache-control": true,
  connection: true,
  expect: true,
  from: true,
  "keep-alive": true,
  "max-forwards": true,
  pragma: true,
  referer: true,
  te: true,
  trailer: true,
  "transfer-encoding": true,
  upgrade: true,
  "user-agent": true,
  "x-amzn-trace-id": true,
};

export const PROXY_HEADER_PATTERN = /^proxy-/;
export const SEC_HEADER_PATTERN = /^sec-/
export const SIGNATURE_QUERY_PARAM = "X-Amz-Signature";
export const SIGNATURE_HEADER = SIGNATURE_QUERY_PARAM.toLowerCase();
export const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
export const GENERATED_HEADERS = [AUTH_HEADER, AMZ_DATE_HEADER, DATE_HEADER];


