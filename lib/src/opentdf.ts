import { type AuthProvider } from './auth/providers.js';
import { ConfigurationError, InvalidFileError } from './errors.js';
import { NanoTDFDatasetClient } from './nanoclients.js';
export { Client as TDF3Client } from '../tdf3/src/client/index.js';
import NanoTDF from './nanotdf/NanoTDF.js';
import decryptNanoTDF from './nanotdf/decrypt.js';
import Client from './nanotdf/Client.js';
import Header from './nanotdf/models/Header.js';
import { fromSource, sourceToStream, type Source } from './seekable.js';
import { Client as TDF3Client } from '../tdf3/src/client/index.js';
import { AssertionConfig, AssertionVerificationKeys } from '../tdf3/src/assertions.js';
import { OriginAllowList } from './access.js';
import { type Manifest } from '../tdf3/src/models/manifest.js';

export type Keys = {
  [keyID: string]: CryptoKey | CryptoKeyPair;
};

// Options when creating a new TDF object
// that are shared between all container types.
export type CreateOptions = {
  // If the policy service should be used to control creation options
  autoconfigure?: boolean;

  // List of attributes that will be assigned to the object's policy
  attributes?: string[];

  // If set and positive, this represents the maxiumum number of bytes to read from a stream to encrypt.
  // This is helpful for enforcing size limits and preventing DoS attacks.
  byteLimit?: number;

  // The KAS to use for creation, if none is specified by the attribute service.
  defaultKASEndpoint?: string;

  // Private (or shared) keys for signing assertions and bindings
  signers?: Keys;

  // Source of plaintext data
  source: Source;
};

export type CreateNanoTDFOptions = CreateOptions & {
  bindingType?: 'ecdsa' | 'gmac';

  // When creating a new collection, use ECDSA binding with this key id from the signers,
  // instead of the DEK.
  ecdsaBindingKeyID?: string;

  // When creating a new collection,
  // use the key in the `signers` list with this id
  // to generate a signature for each element.
  // When absent, the nanotdf is unsigned.
  signingKeyID?: string;
};

export type CreateNanoTDFCollectionOptions = CreateNanoTDFOptions & {
  // The maximum number of key iterations to use for a single DEK.
  maxKeyIterations?: number;
};

// Metadata for a TDF object.
export type Metadata = object;

// MIME type of the decrypted content.
export type MimeType = `${string}/${string}`;

// Template for a Key Access Object (KAO) to be filled in during encrypt.
export type SplitStep = {
  // Which KAS to use to rewrap this segment of the key
  kas: string;

  // An identifier for a key segment.
  // Leave empty to share the key.
  sid?: string;
};

/// Options specific to the ZTDF container format.
export type CreateZTDFOptions = CreateOptions & {
  // Configuration for bound metadata.
  assertionConfigs?: AssertionConfig[];

  // Unbound metadata (deprecated)
  metadata?: Metadata;

  // MIME type of the decrypted content. Used for display.
  mimeType?: MimeType;

  // How to split or share the data encryption key across multiple KASes.
  splitPlan?: SplitStep[];

  // The segment size for the content; smaller is slower, but allows faster random access.
  // The current default is 1 MiB (2^20 bytes).
  windowSize?: number;
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

  // If set, prevents more than this number of concurrent requests to the KAS.
  concurrencyLimit?: number;
};

// Defaults and shared settings that are relevant to creating TDF objects.
export type OpenTDFOptions = {
  // Policy service endpoint
  policyEndpoint?: string;

  // Auth provider for connections to the policy service and KASes.
  authProvider: AuthProvider;

  // Default settings for 'encrypt' type requests.
  defaultCreateOptions?: Omit<CreateOptions, 'source'>;

  // Default settings for 'decrypt' type requests.
  defaultReadOptions?: Omit<ReadOptions, 'source'>;

  // If we want to *not* send a DPoP token
  disableDPoP?: boolean;

  // Optional keys for DPoP requests to a server.
  // These often must be registered via a DPoP flow with the IdP
  // which is out of the scope of this library.
  dpopKeys?: Promise<CryptoKeyPair>;

  // Configuration options for the collection header cache.
  rewrapCacheOptions?: RewrapCacheOptions;
};

export type DecoratedStream = ReadableStream<Uint8Array> & {
  // If the source is a TDF3/ZTDF, and includes metadata, and it has been read.
  metadata?: Promise<any>;
  manifest?: Promise<Manifest>;
  // If the source is a NanoTDF, this will be set.
  header?: Header;
};

// Configuration options for the collection header cache.
export type RewrapCacheOptions = {
  // If we should disable (bypass) the cache.
  bypass?: boolean;

  // Evict keys after this many milliseconds.
  maxAge?: number;

  // Check for expired keys once every this many milliseconds.
  pollInterval?: number;
};

const defaultRewrapCacheOptions: Required<RewrapCacheOptions> = {
  bypass: false,
  maxAge: 300000,
  pollInterval: 500,
};

// Cache for headers of nanotdf collections.
// This allows the SDK to quickly open multiple entries of the same collection.
// It has a demon that removes all keys that have not been accessed in the last 5 minutes.
// To cancel the demon, and clear the cache, call `close()`.
export class RewrapCache {
  private cache?: Map<Uint8Array, { lastAccessTime: number; value: CryptoKey }>;
  private closer?: NodeJS.Timer;
  constructor(opts?: RewrapCacheOptions) {
    const { bypass, maxAge, pollInterval } = { ...defaultRewrapCacheOptions, ...opts };
    if (bypass) {
      return;
    }
    this.cache = new Map();
    this.closer = setInterval(() => {
      const now = Date.now();
      const c = this.cache;
      if (!c) {
        return;
      }
      for (const [key, value] of c.entries()) {
        if (now - value.lastAccessTime > maxAge) {
          c.delete(key);
        }
      }
    }, pollInterval);
  }

  get(key: Uint8Array): CryptoKey | undefined {
    if (!this.cache) {
      return undefined;
    }
    const entry = this.cache.get(key);
    if (entry) {
      entry.lastAccessTime = Date.now();
      return entry.value;
    }
    return undefined;
  }

  set(key: Uint8Array, value: CryptoKey) {
    if (!this.cache) {
      return;
    }
    this.cache.set(key, { lastAccessTime: Date.now(), value });
  }

  close() {
    if (this.closer) {
      clearInterval(this.closer);
      delete this.closer;
      delete this.cache;
    }
  }
}

// SDK for dealing with OpenTDF data and policy services.
export class OpenTDF {
  // Configuration service and more is at this URL/connectRPC endpoint
  readonly policyEndpoint: string;
  readonly authProvider: AuthProvider;
  readonly dpopEnabled: boolean;
  defaultCreateOptions: Omit<CreateOptions, 'source'>;
  defaultReadOptions: Omit<ReadOptions, 'source'>;
  readonly dpopKeys: Promise<CryptoKeyPair>;

  // Header cache for reading nanotdf collections
  private readonly rewrapCache: RewrapCache;
  private tdf3Client: TDF3Client;

  constructor({
    authProvider,
    dpopKeys,
    defaultCreateOptions,
    defaultReadOptions,
    disableDPoP,
    policyEndpoint,
    rewrapCacheOptions,
  }: OpenTDFOptions) {
    this.authProvider = authProvider;
    this.defaultCreateOptions = defaultCreateOptions || {};
    this.defaultReadOptions = defaultReadOptions || {};
    this.dpopEnabled = !!disableDPoP;
    this.policyEndpoint = policyEndpoint || '';
    this.rewrapCache = new RewrapCache(rewrapCacheOptions);
    this.tdf3Client = new TDF3Client({
      authProvider,
      dpopKeys,
      kasEndpoint: 'https://disallow.all.invalid',
      policyEndpoint,
    });
    this.dpopKeys =
      dpopKeys ??
      crypto.subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          hash: 'SHA-256',
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        },
        true,
        ['sign', 'verify']
      );
  }

  async createNanoTDF(opts: CreateNanoTDFOptions): Promise<DecoratedStream> {
    opts = { ...this.defaultCreateOptions, ...opts };
    const collection = await this.createNanoTDFCollection(opts);
    try {
      return await collection.encrypt(opts.source);
    } finally {
      await collection.close();
    }
  }

  /**
   * Creates a new collection object, which can be used to encrypt a series of data with the same policy.
   * @returns
   */
  async createNanoTDFCollection(opts: CreateNanoTDFCollectionOptions): Promise<NanoTDFCollection> {
    opts = { ...this.defaultCreateOptions, ...opts };
    return new Collection(this.authProvider, opts);
  }

  async createZTDF(opts: CreateZTDFOptions): Promise<DecoratedStream> {
    opts = { ...this.defaultCreateOptions, ...opts };
    const oldStream = await this.tdf3Client.encrypt({
      source: await sourceToStream(opts.source),

      assertionConfigs: opts.assertionConfigs,
      autoconfigure: !!opts.autoconfigure,
      defaultKASEndpoint: opts.defaultKASEndpoint,
      byteLimit: opts.byteLimit,
      mimeType: opts.mimeType,
      scope: {
        attributes: opts.attributes,
      },
      splitPlan: opts.splitPlan,
      windowSize: opts.windowSize,
    });
    const stream: DecoratedStream = oldStream.stream;
    stream.manifest = Promise.resolve(oldStream.manifest);
    stream.metadata = Promise.resolve(oldStream.metadata);
    return stream;
  }

  /**
   * Decrypts a nanotdf object. Optionally, stores the collection header and its DEK.
   * @param ciphertext
   */
  async read(opts: ReadOptions): Promise<DecoratedStream> {
    opts = { ...this.defaultReadOptions, ...opts };
    const chunker = await fromSource(opts.source);
    const prefix = await chunker(0, 3);
    // switch for prefix, if starts with `PK` in ascii, or `L1L` in ascii:
    if (prefix[0] === 0x50 && prefix[1] === 0x4b) {
      const allowList = new OriginAllowList(opts.allowedKASEndpoints ?? [], opts.ignoreAllowlist);
      let assertionVerificationKeys: AssertionVerificationKeys | undefined;
      if (opts.verifiers && !opts.noVerify) {
        assertionVerificationKeys = { Keys: {} };
        for (const [keyID, key] of Object.entries(opts.verifiers)) {
          if ((key as CryptoKeyPair).publicKey) {
            const pk = (key as CryptoKeyPair).publicKey;
            const algName = pk.algorithm.name;
            const alg = algName.startsWith('EC') ? 'ES256' : 'RS256';
            assertionVerificationKeys.Keys[keyID] = {
              alg,
              key: pk,
            };
          } else {
            const k = key as CryptoKey;
            const algName = k.algorithm.name;
            const alg = algName.startsWith('AES')
              ? 'HS256'
              : algName.startsWith('EC')
                ? 'ES256'
                : 'RS256';
            assertionVerificationKeys.Keys[keyID] = {
              alg,
              key: k,
            };
          }
        }
      }
      const oldStream = await this.tdf3Client.decrypt({
        source: opts.source,
        allowList,
        assertionVerificationKeys,
        noVerifyAssertions: opts.noVerify,
      });
      const stream: DecoratedStream = oldStream.stream;
      stream.metadata = Promise.resolve(oldStream.metadata);
      return stream;
    } else if (prefix[0] === 0x4c && prefix[1] === 0x31 && prefix[2] === 0x4c) {
      const ciphertext = await chunker();
      const nanotdf = NanoTDF.from(ciphertext);
      const cachedDEK = this.rewrapCache.get(nanotdf.header.ephemeralPublicKey);
      if (cachedDEK) {
        const r: DecoratedStream = await streamify(decryptNanoTDF(cachedDEK, nanotdf));
        r.header = nanotdf.header;
        return r;
      }
      const nc = new Client({
        allowedKases: opts.allowedKASEndpoints,
        authProvider: this.authProvider,
        ignoreAllowList: opts.ignoreAllowlist,
        dpopEnabled: this.dpopEnabled,
        dpopKeys: this.dpopKeys,
        kasEndpoint: opts.allowedKASEndpoints?.[0] || 'https://disallow.all.invalid',
      });
      // TODO: The version number should be fetched from the API
      const version = '0.0.1';
      // Rewrap key on every request
      const dek = await nc.rewrapKey(
        nanotdf.header.toBuffer(),
        nanotdf.header.getKasRewrapUrl(),
        nanotdf.header.magicNumberVersion,
        version
      );
      if (!dek) {
        // These should have thrown already.
        throw new Error('internal: key rewrap failure');
      }
      this.rewrapCache.set(nanotdf.header.ephemeralPublicKey, dek);
      const r: DecoratedStream = await streamify(decryptNanoTDF(dek, nanotdf));
      r.header = nanotdf.header;
      return r;
    }
    throw new InvalidFileError(`unsupported format; prefix not recognized ${prefix}`);
  }

  close() {
    this.rewrapCache.close();
  }
}

async function streamify(ab: Promise<ArrayBuffer>): Promise<ReadableStream<Uint8Array>> {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      ab.then((arrayBuffer) => {
        controller.enqueue(new Uint8Array(arrayBuffer));
        controller.close();
      });
    },
  });
  return stream;
}

export type NanoTDFCollection = {
  encrypt: (source: Source) => Promise<ReadableStream<Uint8Array>>;
  close: () => Promise<void>;
};

class Collection {
  client?: NanoTDFDatasetClient;

  constructor(authProvider: AuthProvider, opts: CreateNanoTDFCollectionOptions) {
    if (opts.signers || opts.signingKeyID) {
      throw new ConfigurationError('ntdf signing not implemented');
    }
    if (opts.autoconfigure) {
      throw new ConfigurationError('autoconfigure not implemented');
    }
    if (opts.ecdsaBindingKeyID) {
      throw new ConfigurationError('custom binding key not implemented');
    }

    this.client = new NanoTDFDatasetClient({
      authProvider,
      kasEndpoint: opts.defaultKASEndpoint ?? 'https://disallow.all.invalid',
      maxKeyIterations: opts.maxKeyIterations,
    });
  }

  async encrypt(source: Source): Promise<DecoratedStream> {
    if (!this.client) {
      throw new ConfigurationError('Collection is closed');
    }
    const chunker = await fromSource(source);
    const cipherChunk = await this.client.encrypt(await chunker());
    const stream: DecoratedStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(cipherChunk));
        controller.close();
      },
    });
    // TODO: client's header object is private
    // stream.header = this.client.header;
    return stream;
  }

  async close() {
    delete this.client;
  }
}
