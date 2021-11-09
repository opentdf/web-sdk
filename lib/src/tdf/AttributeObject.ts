export default interface AttributeObject {
  readonly attribute: string;
  readonly isDefault: boolean;
  readonly displayName: string;
  /** PEM encoded public key */
  readonly pubKey: string;
  readonly kasUrl: string;
  /** The most recent version 1.1.0. */
  readonly schemaVersion?: string;
}

export function createAttribute(
  attribute: string,
  pubKey: string,
  kasUrl: string
): AttributeObject {
  return {
    attribute: attribute,
    isDefault: false,
    displayName: '',
    pubKey: pubKey,
    kasUrl: kasUrl,
    schemaVersion: '1.1.0',
  };
}
