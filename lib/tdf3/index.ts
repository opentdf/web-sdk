import { Binary } from './src/binary.js';
import { DecoratedReadableStream } from './src/client/DecoratedReadableStream.js';
import {
  type DecryptParams,
  DecryptParamsBuilder,
  type DecryptSource,
  type EncryptParams,
  type EncryptKeyMiddleware,
  type EncryptStreamMiddleware,
  type DecryptKeyMiddleware,
  type DecryptStreamMiddleware,
  EncryptParamsBuilder,
  type SplitStep,
} from './src/client/builders.js';
import { type ClientConfig, createSessionKeys } from './src/client/index.js';
import {
  type AsymmetricSigningAlgorithm,
  type CryptoService,
  type DecryptResult,
  type ECCurve,
  type EncryptResult,
  type HashAlgorithm,
  type HkdfParams,
  type KeyPair,
  type PemKeyPair,
  type PrivateKey,
  type PublicKey,
  type PublicKeyInfo,
  type SigningAlgorithm,
  type SymmetricKey,
  type SymmetricSigningAlgorithm,
} from './src/crypto/declarations.js';
import { Client, Errors, TDF3Client } from './src/index.js';
import {
  type KeyInfo,
  SplitKey,
  type EncryptionInformation,
} from './src/models/encryption-information.js';
import { AuthProvider, type HttpMethod, HttpRequest, withHeaders } from '../src/auth/auth.js';
import { AesGcmCipher } from './src/ciphers/aes-gcm-cipher.js';
import * as AuthProviders from '../src/auth/providers.js';
import { version, clientType } from '../src/version.js';
import { Algorithms, type AlgorithmName, type AlgorithmUrn } from './src/ciphers/algorithms.js';
import { type Chunker } from '../src/seekable.js';

export type {
  AlgorithmName,
  AlgorithmUrn,
  AsymmetricSigningAlgorithm,
  AuthProvider,
  Chunker,
  CryptoService,
  DecryptKeyMiddleware,
  DecryptResult,
  DecryptStreamMiddleware,
  ECCurve,
  EncryptKeyMiddleware,
  EncryptResult,
  EncryptStreamMiddleware,
  HashAlgorithm,
  HkdfParams,
  HttpMethod,
  KeyPair,
  PemKeyPair,
  PrivateKey,
  PublicKey,
  PublicKeyInfo,
  SigningAlgorithm,
  SplitStep,
  SymmetricKey,
  SymmetricSigningAlgorithm,
};

export {
  AesGcmCipher,
  Algorithms,
  AuthProviders,
  Binary,
  Client,
  ClientConfig,
  DecoratedReadableStream,
  DecryptParams,
  DecryptParamsBuilder,
  DecryptSource,
  EncryptionInformation,
  EncryptParams,
  EncryptParamsBuilder,
  Errors,
  HttpRequest,
  KeyInfo,
  SplitKey,
  TDF3Client,
  clientType,
  createSessionKeys,
  withHeaders,
  version,
};

export { DefaultCryptoService as WebCryptoService } from './src/crypto/index.js';
// export the other methods from crypto/index.js that aren't part of CryptoService but are needed for JWT handling
export {
  type CreateOptions,
  type CreateZTDFOptions,
  type DecoratedStream,
  type Keys,
  type OpenTDFOptions,
  type ReadOptions,
  type TDFReader,
  OpenTDF,
} from '../src/opentdf.js';
