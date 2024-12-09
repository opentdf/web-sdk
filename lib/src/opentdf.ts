import { AuthProvider } from "./auth/providers.js";
import { NanoTDFDatasetClient } from "./index.js";
import { Source } from "./chunkers.js";

export type Keys = {
  [keyID: string]: CryptoKey|CryptoKeyPair;
};

// Options when creating a new TDF object
// that are shared between all container types.
export type CreateOptions = {
  // The KAS to use for creation, if none is specified by the attribute service.
  defaultKASEndpoint: string;
  // Private (or shared) keys for signing assertions and bindings
  signers?: Keys;
  // List of attributes that will be assigned to the object's policy
  attributes?: string[];
  // If the policy service should be used to control creation options
  autoconfigure?: boolean;
};

export type CreateNanoOptions = CreateOptions & {
  // When creating a new collection, use ECDSA binding with this key id from the signers, 
  // instead of the DEK.
  ecdsaBindingKeyID?: string;

  // When creating a new collection,
  // use the key in the `signers` list with this id
  // to generate a signature for each element.
  // When absent, the nanotdf is unsigned.
  signingKeyID?: string;
};
;

export type CreateNanoTDFCollectionOptions = CreateNanoOptions & {
  // The maximum number of key iterations to use for a single DEK.
  maxKeyIterations?: number
};

export type CreateNanoTDFOptions = CreateOptions & {
  // Source of plaintext data
  source: Source;

  // When creating a new collection, use ECDSA binding with this key id from the signers, instead of the DEK.
  ecdsaBindingKeyID?: string;

  // When creating a new collection, use this to generate a signature for each element.
  signingKeyID?: string;
};

// Settings for decrypting any variety of TDF file.
export type ReadOptions = {
  // ciphertext
  source: Source;
  // list of KASes that may be contacted for a rewrap
  allowedKASEndpoints?: string[];
  // Optionally disable checking the allowlist
  ignoreAllowlist?: boolean;
  // Public (or shared) keys for verifying assertions
  verifiers?: Keys;
  // Optionally disable assertion verification
  noVerify?: boolean;
};

// Defaults and shared settings that are relevant to creating TDF objects.
export type OpenTDFOptions = {
  // Policy service endpoint
  policyEndpoint: string;

  // Default settings for 'encrypt' type requests.
  defaultCreateOptions: CreateOptions;

  // Default settings for 'decrypt' type requests.
  defaultReadOptions: ReadOptions;

  // If we want to *not* send a DPoP token
  disableDPoP: boolean;

  authProvider: AuthProvider;
};

export type DecoratedStream = ReadableStream<Uint8Array> & {
  metadata: Promise<any>;
};

// SDK for dealing with OpenTDF data and policy services. 
export class OpenTDF {
  // Configuration service and more is at this URL/connectRPC endpoint
  readonly policyEndpoint: string;
  readonly authProvider: AuthProvider;
  readonly dpopEnabled: boolean;
  defaultCreateOptions: CreateOptions;
  defaultReadOptions: ReadOptions;

  // Header cache for reading nanotdf collections
  // TODO readonly private headerCache: NanoHeaderCache;

  constructor({authProvider, defaultCreateOptions, defaultReadOptions, disableDPoP, policyEndpoint}: OpenTDFOptions) {
    this.authProvider = authProvider;
    this.defaultCreateOptions = defaultCreateOptions;
    this.defaultReadOptions = defaultReadOptions;
    this.dpopEnabled = !!disableDPoP;
    this.policyEndpoint = policyEndpoint;
  }

  async createNanoTDF(opts: CreateNanoTDFOptions): Promise<ArrayBuffer> {
    const collection = await this.createNanoTDFCollection(opts);
    const ciphertext = await collection.encrypt(opts.source);
    await collection.close();
    return ciphertext;
  }

  /**
   * Creates a new collection object, which can be used to encrypt a series of data with the same policy. 
   * @returns 
   */
  async createNanoTDFCollection(opts: CreateNanoTDFCollectionOptions): Promise<NanoTDFCollection> {
    const c = new Collection(opts);
    throw new Error('Not implemented');
  }

  /**
   * Decrypts a nanotdf object. Optionally, stores the collection header and its DEK.
   * @param ciphertext 
   */
  async read(opts?: ReadOptions): Promise<DecoratedStream> {
    throw new Error('Not implemented');
  }
}

export type NanoTDFCollection = {
  encrypt: (source: Source) => Promise<ArrayBuffer>;
  close: () => Promise<void>;
};

class Collection {
  client: NanoTDFDatasetClient;

  constructor(authProvider: AuthProvider, opts: CreateNanoTDFCollectionOptions) {
    if (opts.signers || opts.signingKeyID) {
      throw new Error('ntdf signing not implemented');
    }
    if (opts.autoconfigure) {
      throw new Error('autoconfigure not implemented');
    }
    if (opts.ecdsaBindingKeyID) {
      throw new Error('custom binding key not implemented');
    }

    this.client = new NanoTDFDatasetClient({
      authProvider,
      kasEndpoint: opts.defaultKASEndpoint,
      maxKeyIterations: opts.maxKeyIterations,
    });
  }

  async encrypt(source: Source): Promise<ArrayBuffer> {
    return this.client.encrypt(source);
    throw new Error('Not implemented');
  }

}