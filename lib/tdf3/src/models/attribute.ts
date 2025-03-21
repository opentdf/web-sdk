/**
 * Information about a data or entity attribute, its meaning and interpretation.
 * While usually we just refer to an attribute by its URL,
 * we often need to store additional information about it,
 * for display or analysis.
 */
export type AttributeObject = {
  // The fully qualified name of the attribute, generally a URL
  attribute: string;
  // Optional descriptive name of the attribute
  displayName?: string;
  // Indicates a default attribute, usually for all policies associated with a KAS
  isDefault?: boolean;

  // Optional: A cryptographically bound version of the attribute. Deprecated: use a JWS with this as the payload.
  jwt?: string;

  // A KAS that is associated with the attribute.
  kasUrl?: string;

  // The preferred public key for the attribute
  kid?: string;

  // The public key value for the attribute
  pubKey?: string;
};
