import { KasPublicKeyInfo } from 'src/access.js';

export interface AttributeObject {
  readonly attribute: string;
  readonly isDefault?: boolean;
  readonly displayName?: string;
  /** PEM encoded public key */
  readonly pubKey: string;
  readonly kasUrl: string;
  /** The most recent version 1.1.0. */
  readonly schemaVersion?: string;
}

export async function createAttribute(
  attribute: string,
  pubKey: KasPublicKeyInfo,
  kasUrl: string
): Promise<AttributeObject> {
  return {
    attribute,
    isDefault: false,
    displayName: '',
    pubKey: pubKey.publicKey,
    kasUrl,
    schemaVersion: '1.1.0',
  };
}
