export type Metadata = {
  /**
   * created_at set by server (entity who created will recorded in an audit event)
   * Format: date-time
   */
  createdAt?: string;

  /**
   * updated_at set by server (entity who updated will recorded in an audit event)
   * Format: date-time
   */
  updatedAt?: string;

  /** optional short description */
  labels?: Record<string, string>;
};

export type KasPublicKeyAlgorithm =
  | 'KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED'
  | 'KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048'
  | 'KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1';

export type KasPublicKey = {
  /** x509 ASN.1 content in PEM envelope, usually */
  pem: string;
  /** A unique string identifier for this key */
  kid: string;
  /**
   * @description A known algorithm type with any additional parameters encoded.
   * To start, these may be `rsa:2048` for encrypting ZTDF files and
   * `ec:secp256r1` for nanoTDF, but more formats may be added as needed.
   */
  alg: KasPublicKeyAlgorithm;
};

export type KasPublicKeySet = {
  keys: KasPublicKey[];
};

export type PublicKey = {
  /** kas public key url - optional since can also be retrieved via public key */
  remote?: string;
  /** public key; PEM of RSA public key; prefer `cached` */
  local?: string;
  /** public key with additional information. Current preferred version */
  cached?: KasPublicKeySet;
};

export type KeyAccessServer = {
  id?: string;
  /** Address of a KAS instance */
  uri: string;
  publicKey?: PublicKey;
  metadata?: Metadata;
};

export type Namespace = {
  /** uuid */
  id?: string;
  /** used to partition Attribute Definitions, support by namespace AuthN and enable federation */
  name?: string;
  fqn: string;
  /** active by default until explicitly deactivated */
  active?: boolean;
  metadata?: Metadata;
  grants?: KeyAccessServer[];
};

export type AttributeRuleType =
  | 'ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED'
  | 'ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF'
  | 'ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF'
  | 'ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY';

export type Attribute = {
  /** UUID */
  id?: string;
  namespace?: Namespace;
  /** attribute name */
  name?: string;
  /** attribute rule enum */
  rule?: AttributeRuleType;
  values?: Value[];
  grants?: KeyAccessServer[];
  fqn: string;
  /** active by default until explicitly deactivated */
  active?: boolean;
  /** Common metadata */
  metadata?: Metadata;
};

// This is not currently needed by the client, but may be returned.
// Setting it to unknown to allow it to be ignored for now.
export type SubjectMapping = unknown;

export type Value = {
  id?: string;
  attribute?: Attribute;
  value?: string;
  /** list of key access servers */
  grants?: KeyAccessServer[];
  fqn: string;
  /** active by default until explicitly deactivated */
  active?: boolean;
  subjectMappings?: SubjectMapping[];
  /** Common metadata */
  metadata?: Metadata;
};

export type AttributeAndValue = {
  attribute: Attribute;
  value: Value;
};
