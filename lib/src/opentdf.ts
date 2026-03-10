import { type AuthProvider } from './auth/providers.js';
import { ConfigurationError, InvalidFileError } from './errors.js';
export { Client as TDF3Client } from '../tdf3/src/client/index.js';
import { Chunker, fromSource, sourceToStream, type Source } from './seekable.js';
import { Client as TDF3Client } from '../tdf3/src/client/index.js';
import { type CryptoService, type KeyPair } from '../tdf3/src/crypto/declarations.js';
import * as DefaultCryptoService from '../tdf3/src/crypto/index.js';
import {
  type Assertion,
  AssertionConfig,
  AssertionVerificationKeys,
} from '../tdf3/src/assertions.js';
import {
  type KasPublicKeyAlgorithm,
  OriginAllowList,
  fetchKeyAccessServers,
  isPublicKeyAlgorithm,
} from './access.js';
import { type Manifest } from '../tdf3/src/models/manifest.js';
import { type Payload } from '../tdf3/src/models/payload.js';
import {
  type Segment,
  type SplitType,
  type EncryptionInformation,
} from '../tdf3/src/models/encryption-information.js';
import { type KeyAccessObject } from '../tdf3/src/models/key-access.js';
import {
  decryptStreamFrom,
  InspectedTDFOverview,
  loadTDFStream,
  type IntegrityAlgorithm,
} from '../tdf3/src/tdf.js';
import { base64 } from './encodings/index.js';
import { Policy } from '../tdf3/src/models/policy.js';

export {
  type Assertion,
  type CryptoService,
  type EncryptionInformation,
  type IntegrityAlgorithm,
  type KasPublicKeyAlgorithm,
  type KeyAccessObject,
  type Manifest,
  type Payload,
  type Segment,
  type SplitType,
  isPublicKeyAlgorithm,
};

/** A map of key identifiers to cryptographic keys. */
export type Keys = {
  [keyID: string]: CryptoKey | CryptoKeyPair;
};

/** The fully qualified obligations that the caller is required to fulfill. */
export type RequiredObligations = {
  /** List of obligations values' fully qualified names. */
  fqns: string[];
};

/** Options for creating a new TDF object, shared between all container types. */
export type CreateOptions = {
  /** If the policy service should be used to control creation options. */
  autoconfigure?: boolean;

  /** List of attributes that will be assigned to the object's policy. */
  attributes?: string[];

  /**
   * If set and positive, this represents the maxiumum number of bytes to read from a stream to encrypt.
   * This is helpful for enforcing size limits and preventing DoS attacks.
   */
  byteLimit?: number;

  /** The KAS to use for creation, if none is specified by the attribute service. */
  defaultKASEndpoint?: string;

  /** Private (or shared) keys for signing assertions and bindings. */
  signers?: Keys;

  /** Source of plaintext data. */
  source: Source;
};

/** Metadata for a TDF object. */
export type Metadata = object;

/** MIME type of the decrypted content. */
export type MimeType = `${string}/${string}`;

/** Template for a Key Access Object (KAO) to be filled in during encrypt. */
export type SplitStep = {
  /** Which KAS to use to rewrap this segment of the key. */
  kas: string;
  /**
   * An identifier for a key segment.
   * Leave empty to share the key.
   */
  sid?: string;
};

/** Options specific to the ZTDF container format. */
export type CreateZTDFOptions = CreateOptions & {
  /** Configuration for bound metadata. */
  assertionConfigs?: AssertionConfig[];

  /** Unbound metadata (deprecated). */
  metadata?: Metadata;

  /** MIME type of the decrypted content. Used for display. */
  mimeType?: MimeType;

  /** How to split or share the data encryption key across multiple KASes. */
  splitPlan?: SplitStep[];

  /**
   * The segment size for the content; smaller is slower, but allows faster random access.
   * The current default is 1 MiB (2^20 bytes).
   */
  windowSize?: number;

  /** Preferred algorithm to use for Key Access Objects. */
  wrappingKeyAlgorithm?: KasPublicKeyAlgorithm;

  /** TDF spec version to target. */
  tdfSpecVersion?: '4.2.2' | '4.3.0';
};

/** Settings for decrypting any variety of TDF file. */
export type ReadOptions = {
  /** The ciphertext source. */
  source: Source;
  /** The platform URL. */
  platformUrl?: string;
  /** List of KASes that may be contacted for a rewrap. */
  allowedKASEndpoints?: string[];
  /** Optionally disable checking the allowlist. */
  ignoreAllowlist?: boolean;
  /** Optionally override client fulfillableObligationFQNs. */
  fulfillableObligationFQNs?: string[];
  /** Public (or shared) keys for verifying assertions. */
  assertionVerificationKeys?: AssertionVerificationKeys;
  /** Optionally disable assertion verification. */
  noVerify?: boolean;

  /** If set, prevents more than this number of concurrent requests to the KAS. */
  concurrencyLimit?: number;

  /** Type of key to use for wrapping responses. */
  wrappingKeyAlgorithm?: KasPublicKeyAlgorithm;
};

/** Defaults and shared settings that are relevant to creating TDF objects. */
export type OpenTDFOptions = {
  /** Policy service endpoint. */
  policyEndpoint?: string;

  /** Platform URL. */
  platformUrl?: string;

  /** Auth provider for connections to the policy service and KASes. */
  authProvider: AuthProvider;

  /** Default settings for 'encrypt' type requests. */
  defaultCreateOptions?: Omit<CreateOptions, 'source'>;

  /** Default settings for 'decrypt' type requests. */
  defaultReadOptions?: Omit<ReadOptions, 'source'>;

  /** If we want to *not* send a DPoP token. */
  disableDPoP?: boolean;

  /**
   * Optional keys for DPoP requests to a server.
   * These often must be registered via a DPoP flow with the IdP
   * which is out of the scope of this library.
   */
  dpopKeys?: Promise<KeyPair>;

  /**
   * Optional custom CryptoService implementation.
   * If not provided, defaults to the browser's native Web Crypto API.
   * This allows injecting HSM-backed or other secure crypto implementations.
   */
  cryptoService?: CryptoService;
};

/** A decorated readable stream. */
export type DecoratedStream = ReadableStream<Uint8Array> & {
  /** If the source is a TDF3/ZTDF, and includes metadata, and it has been read. */
  metadata?: Promise<unknown>;
  /** The TDF manifest. */
  manifest?: Promise<Manifest>;
};

/**
 * A TDF reader that can decrypt and inspect a TDF file.
 */
export type TDFReader = {
  /**
   * Decrypt the payload.
   */
  decrypt: () => Promise<DecoratedStream>;
  /**
   * Mark this reader as closed and release any resources, such as open files.
   */
  close: () => Promise<void>;

  /**
   * Only present on ZTDF files
   */
  manifest: () => Promise<Manifest>;

  /**
   * @returns Any data attributes found in the policy. Currently only works for plain text, embedded policies (not remote or encrypted policies)
   */
  attributes: () => Promise<string[]>;

  /**
   * @returns Any obligation value FQNs that are required to be fulfilled on the TDF, populated during the decrypt flow.
   */
  obligations: () => Promise<RequiredObligations>;
};

/**
 * The main OpenTDF class that provides methods for creating and reading TDF files.
 * It can be used to create new TDF files and read existing ones.
 * This class is the entry point for using the OpenTDF SDK.
 * It requires an authentication provider to be passed in the constructor.
 * It also requires a platform URL to be set, which is used to fetch key access servers and policies.
 * @example
 * ```
 * import { type Chunker, OpenTDF } from '@opentdf/sdk';
 *
 * const oidcCredentials: RefreshTokenCredentials = {
 *   clientId: keycloakClientId,
 *   exchange: 'refresh',
 *   refreshToken: refreshToken,
 *   oidcOrigin: keycloakUrl,
 * };
 * const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
 *
 * const client = new OpenTDF({
 *   authProvider,
 *   platformUrl: 'https://platform.example.com',
 * });
 *
 * const cipherText = await client.createZTDF({
 *   source: { type: 'stream', location: source },
 *   autoconfigure: false,
 * });
 *
 * const clearText = await client.read({ type: 'stream', location: cipherText });
 * ```
 */
export class OpenTDF {
  /** The platform URL */
  readonly platformUrl: string;
  /** The policy service endpoint */
  readonly policyEndpoint: string;
  /** The auth provider for the OpenTDF instance. */
  readonly authProvider: AuthProvider;
  /** If DPoP is enabled for this instance. */
  readonly dpopEnabled: boolean;
  /** Default options for creating TDF objects. */
  defaultCreateOptions: Omit<CreateOptions, 'source'>;
  /** Default options for reading TDF objects. */
  defaultReadOptions: Omit<ReadOptions, 'source'>;
  /** The DPoP keys for this instance, if any. */
  readonly dpopKeys: Promise<KeyPair>;
  /** The CryptoService implementation for this instance. */
  readonly cryptoService: CryptoService;
  /** The TDF3 client for encrypting and decrypting ZTDF files. */
  readonly tdf3Client: TDF3Client;

  constructor({
    authProvider,
    dpopKeys,
    defaultCreateOptions,
    defaultReadOptions,
    disableDPoP,
    policyEndpoint,
    platformUrl,
    cryptoService,
  }: OpenTDFOptions) {
    this.authProvider = authProvider;
    this.defaultCreateOptions = defaultCreateOptions || {};
    this.defaultReadOptions = defaultReadOptions || {};
    this.dpopEnabled = !!disableDPoP;
    if (platformUrl) {
      this.platformUrl = platformUrl;
    } else {
      console.warn(
        "Warning: 'platformUrl' is required for security to ensure the SDK uses the platform-configured Key Access Server list"
      );
    }
    this.policyEndpoint = policyEndpoint || '';
    this.cryptoService = cryptoService ?? DefaultCryptoService;
    this.tdf3Client = new TDF3Client({
      authProvider,
      dpopKeys,
      kasEndpoint: this.platformUrl || 'https://disallow.all.invalid',
      platformUrl,
      policyEndpoint,
      cryptoService: this.cryptoService,
    });
    // Use CryptoService for key generation (returns opaque KeyPair)
    this.dpopKeys = dpopKeys ?? this.cryptoService.generateSigningKeyPair();
  }

  /** Creates a new ZTDF stream. */
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
      wrappingKeyAlgorithm: opts.wrappingKeyAlgorithm,
      tdfSpecVersion: opts.tdfSpecVersion,
    });
    const stream: DecoratedStream = oldStream.stream;
    stream.manifest = Promise.resolve(oldStream.manifest);
    stream.metadata = Promise.resolve(oldStream.metadata);
    return stream;
  }

  /** Opens a TDF file for inspection and decryption. */
  open(opts: ReadOptions): TDFReader {
    opts = { ...this.defaultReadOptions, ...opts };
    return new ZTDFReaderWrapper(this, opts);
  }

  /** Decrypts a TDF file. */
  async read(opts: ReadOptions): Promise<DecoratedStream> {
    const reader = this.open(opts);
    return reader.decrypt();
  }

  /** Closes the OpenTDF instance and releases any resources. */
  close() {
    // No-op for now, but kept for API compatibility
  }
}

/** A TDF reader wrapper that handles ZTDF files. */
class ZTDFReaderWrapper {
  delegate: Promise<TDFReader>;
  state: 'init' | 'resolving' | 'loaded' | 'decrypting' | 'closing' | 'done' | 'error' = 'init';
  constructor(
    readonly outer: OpenTDF,
    readonly opts: ReadOptions
  ) {
    this.delegate = this.resolveType();
  }

  /** Resolves the TDF type based on the file prefix. */
  async resolveType(): Promise<TDFReader> {
    if (this.state === 'done') {
      throw new ConfigurationError('reader is closed');
    }
    this.state = 'resolving';
    const chunker = await fromSource(this.opts.source);
    const prefix = await chunker(0, 3);
    if (!this.opts.platformUrl && this.outer.platformUrl) {
      this.opts.platformUrl = this.outer.platformUrl;
    }
    if (prefix[0] === 0x50 && prefix[1] === 0x4b) {
      this.state = 'loaded';
      return new ZTDFReader(this.outer.tdf3Client, this.opts, chunker);
    }
    this.state = 'done';
    throw new InvalidFileError(`unsupported format; prefix not recognized ${prefix}`);
  }

  /** Decrypts the TDF file */
  async decrypt(): Promise<DecoratedStream> {
    const actual = await this.delegate;
    return actual.decrypt();
  }

  /** Returns the attributes of the TDF file */
  async attributes(): Promise<string[]> {
    const actual = await this.delegate;
    return actual.attributes();
  }

  /** Returns the manifest of the TDF file */
  async manifest(): Promise<Manifest> {
    const actual = await this.delegate;
    return actual.manifest();
  }

  /** Closes the TDF reader */
  async close() {
    if (this.state === 'done') {
      return;
    }
    if (this.state === 'init') {
      // delegate resolve never started
      this.state = 'done';
      return;
    }
    this.state = 'closing';
    const actual = await this.delegate;
    return actual.close().then(() => {
      this.state = 'done';
    });
  }

  async obligations() {
    const actual = await this.delegate;
    return actual.obligations();
  }
}

/** A reader for ZTDF files. */
class ZTDFReader {
  overview: Promise<InspectedTDFOverview>;
  // Required obligation FQNs that must be fulfilled, provided via the decrypt flow.
  private requiredObligations?: RequiredObligations;
  constructor(
    readonly client: TDF3Client,
    readonly opts: ReadOptions,
    readonly source: Chunker
  ) {
    this.overview = loadTDFStream(source);
  }

  /**
   * Decrypts the TDF file and returns a decorated stream.
   * The stream will have a manifest and metadata attached if available.
   * Sets required obligations on the reader when retrieved from KAS rewrap response.
   */
  async decrypt(): Promise<DecoratedStream> {
    const {
      assertionVerificationKeys,
      noVerify: noVerifyAssertions,
      wrappingKeyAlgorithm,
    } = this.opts;

    if (!this.opts.ignoreAllowlist && !this.opts.allowedKASEndpoints && !this.opts.platformUrl) {
      throw new ConfigurationError('platformUrl is required when allowedKasEndpoints is empty');
    }

    const dpopKeys = await this.client.dpopKeys;

    const { authProvider, cryptoService } = this.client;
    if (!authProvider) {
      throw new ConfigurationError('authProvider is required');
    }

    let allowList: OriginAllowList | undefined;

    if (this.opts.allowedKASEndpoints?.length || this.opts.ignoreAllowlist) {
      allowList = new OriginAllowList(
        this.opts.allowedKASEndpoints || [],
        this.opts.ignoreAllowlist
      );
    } else if (this.opts.platformUrl) {
      allowList = await fetchKeyAccessServers(this.opts.platformUrl, authProvider);
    }

    const overview = await this.overview;
    const oldStream = await decryptStreamFrom(
      {
        allowList,
        authProvider,
        chunker: this.source,
        concurrencyLimit: 1,
        cryptoService,
        dpopKeys,
        fileStreamServiceWorker: this.client.clientConfig.fileStreamServiceWorker,
        keyMiddleware: async (k) => k,
        progressHandler: this.client.clientConfig.progressHandler,
        assertionVerificationKeys,
        noVerifyAssertions,
        wrappingKeyAlgorithm,
        fulfillableObligations: this.opts.fulfillableObligationFQNs || [],
      },
      overview
    );
    this.requiredObligations = {
      fqns: oldStream.obligations(),
    };
    const stream: DecoratedStream = oldStream.stream;
    stream.manifest = Promise.resolve(overview.manifest);
    stream.metadata = Promise.resolve(oldStream.metadata);
    return stream;
  }

  async close() {
    // TODO figure out how to close a chunker, if we want to.
  }

  /** Returns the manifest of the TDF file. */
  async manifest(): Promise<Manifest> {
    const overview = await this.overview;
    return overview.manifest;
  }

  /** Returns the attributes of the TDF file. */
  async attributes(): Promise<string[]> {
    const manifest = await this.manifest();
    const policyJSON = base64.decode(manifest.encryptionInformation.policy);
    const policy = JSON.parse(policyJSON) as Policy;
    return policy?.body?.dataAttributes.map((a) => a.attribute) || [];
  }

  /**
   * Returns obligations populated from the decrypt flow.
   * If a decrypt has not occurred, attempts one to retrieve obligations.
   */
  async obligations(): Promise<RequiredObligations> {
    if (this.requiredObligations) {
      return this.requiredObligations;
    }
    await this.decrypt();
    return this.requiredObligations ?? { fqns: [] };
  }
}
