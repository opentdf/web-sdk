import * as jspb from 'google-protobuf'

import * as google_api_annotations_pb from '../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as google_protobuf_struct_pb from 'google-protobuf/google/protobuf/struct_pb'; // proto import: "google/protobuf/struct.proto"
import * as google_protobuf_wrappers_pb from 'google-protobuf/google/protobuf/wrappers_pb'; // proto import: "google/protobuf/wrappers.proto"
import * as protoc$gen$openapiv2_options_annotations_pb from '../protoc-gen-openapiv2/options/annotations_pb'; // proto import: "protoc-gen-openapiv2/options/annotations.proto"


export class InfoRequest extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): InfoRequest.AsObject;
  static toObject(includeInstance: boolean, msg: InfoRequest): InfoRequest.AsObject;
  static serializeBinaryToWriter(message: InfoRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): InfoRequest;
  static deserializeBinaryFromReader(message: InfoRequest, reader: jspb.BinaryReader): InfoRequest;
}

export namespace InfoRequest {
  export type AsObject = {
  }
}

export class InfoResponse extends jspb.Message {
  getVersion(): string;
  setVersion(value: string): InfoResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): InfoResponse.AsObject;
  static toObject(includeInstance: boolean, msg: InfoResponse): InfoResponse.AsObject;
  static serializeBinaryToWriter(message: InfoResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): InfoResponse;
  static deserializeBinaryFromReader(message: InfoResponse, reader: jspb.BinaryReader): InfoResponse;
}

export namespace InfoResponse {
  export type AsObject = {
    version: string,
  }
}

export class LegacyPublicKeyRequest extends jspb.Message {
  getAlgorithm(): string;
  setAlgorithm(value: string): LegacyPublicKeyRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): LegacyPublicKeyRequest.AsObject;
  static toObject(includeInstance: boolean, msg: LegacyPublicKeyRequest): LegacyPublicKeyRequest.AsObject;
  static serializeBinaryToWriter(message: LegacyPublicKeyRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): LegacyPublicKeyRequest;
  static deserializeBinaryFromReader(message: LegacyPublicKeyRequest, reader: jspb.BinaryReader): LegacyPublicKeyRequest;
}

export namespace LegacyPublicKeyRequest {
  export type AsObject = {
    algorithm: string,
  }
}

export class PublicKeyRequest extends jspb.Message {
  getAlgorithm(): string;
  setAlgorithm(value: string): PublicKeyRequest;

  getFmt(): string;
  setFmt(value: string): PublicKeyRequest;

  getV(): string;
  setV(value: string): PublicKeyRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): PublicKeyRequest.AsObject;
  static toObject(includeInstance: boolean, msg: PublicKeyRequest): PublicKeyRequest.AsObject;
  static serializeBinaryToWriter(message: PublicKeyRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): PublicKeyRequest;
  static deserializeBinaryFromReader(message: PublicKeyRequest, reader: jspb.BinaryReader): PublicKeyRequest;
}

export namespace PublicKeyRequest {
  export type AsObject = {
    algorithm: string,
    fmt: string,
    v: string,
  }
}

export class PublicKeyResponse extends jspb.Message {
  getPublicKey(): string;
  setPublicKey(value: string): PublicKeyResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): PublicKeyResponse.AsObject;
  static toObject(includeInstance: boolean, msg: PublicKeyResponse): PublicKeyResponse.AsObject;
  static serializeBinaryToWriter(message: PublicKeyResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): PublicKeyResponse;
  static deserializeBinaryFromReader(message: PublicKeyResponse, reader: jspb.BinaryReader): PublicKeyResponse;
}

export namespace PublicKeyResponse {
  export type AsObject = {
    publicKey: string,
  }
}

export class RewrapRequest extends jspb.Message {
  getSignedRequestToken(): string;
  setSignedRequestToken(value: string): RewrapRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RewrapRequest.AsObject;
  static toObject(includeInstance: boolean, msg: RewrapRequest): RewrapRequest.AsObject;
  static serializeBinaryToWriter(message: RewrapRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RewrapRequest;
  static deserializeBinaryFromReader(message: RewrapRequest, reader: jspb.BinaryReader): RewrapRequest;
}

export namespace RewrapRequest {
  export type AsObject = {
    signedRequestToken: string,
  }
}

export class RewrapResponse extends jspb.Message {
  getMetadataMap(): jspb.Map<string, google_protobuf_struct_pb.Value>;
  clearMetadataMap(): RewrapResponse;

  getEntityWrappedKey(): Uint8Array | string;
  getEntityWrappedKey_asU8(): Uint8Array;
  getEntityWrappedKey_asB64(): string;
  setEntityWrappedKey(value: Uint8Array | string): RewrapResponse;

  getSessionPublicKey(): string;
  setSessionPublicKey(value: string): RewrapResponse;

  getSchemaVersion(): string;
  setSchemaVersion(value: string): RewrapResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RewrapResponse.AsObject;
  static toObject(includeInstance: boolean, msg: RewrapResponse): RewrapResponse.AsObject;
  static serializeBinaryToWriter(message: RewrapResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RewrapResponse;
  static deserializeBinaryFromReader(message: RewrapResponse, reader: jspb.BinaryReader): RewrapResponse;
}

export namespace RewrapResponse {
  export type AsObject = {
    metadataMap: Array<[string, google_protobuf_struct_pb.Value.AsObject]>,
    entityWrappedKey: Uint8Array | string,
    sessionPublicKey: string,
    schemaVersion: string,
  }
}

