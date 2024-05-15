import * as jspb from 'google-protobuf'

import * as buf_validate_validate_pb from '../../buf/validate/validate_pb'; // proto import: "buf/validate/validate.proto"
import * as common_common_pb from '../../common/common_pb'; // proto import: "common/common.proto"
import * as google_api_annotations_pb from '../../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as policy_objects_pb from '../../policy/objects_pb'; // proto import: "policy/objects.proto"


export class GetKeyAccessServerRequest extends jspb.Message {
  getId(): string;
  setId(value: string): GetKeyAccessServerRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetKeyAccessServerRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetKeyAccessServerRequest): GetKeyAccessServerRequest.AsObject;
  static serializeBinaryToWriter(message: GetKeyAccessServerRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetKeyAccessServerRequest;
  static deserializeBinaryFromReader(message: GetKeyAccessServerRequest, reader: jspb.BinaryReader): GetKeyAccessServerRequest;
}

export namespace GetKeyAccessServerRequest {
  export type AsObject = {
    id: string,
  }
}

export class GetKeyAccessServerResponse extends jspb.Message {
  getKeyAccessServer(): policy_objects_pb.KeyAccessServer | undefined;
  setKeyAccessServer(value?: policy_objects_pb.KeyAccessServer): GetKeyAccessServerResponse;
  hasKeyAccessServer(): boolean;
  clearKeyAccessServer(): GetKeyAccessServerResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetKeyAccessServerResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetKeyAccessServerResponse): GetKeyAccessServerResponse.AsObject;
  static serializeBinaryToWriter(message: GetKeyAccessServerResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetKeyAccessServerResponse;
  static deserializeBinaryFromReader(message: GetKeyAccessServerResponse, reader: jspb.BinaryReader): GetKeyAccessServerResponse;
}

export namespace GetKeyAccessServerResponse {
  export type AsObject = {
    keyAccessServer?: policy_objects_pb.KeyAccessServer.AsObject,
  }
}

export class ListKeyAccessServersRequest extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListKeyAccessServersRequest.AsObject;
  static toObject(includeInstance: boolean, msg: ListKeyAccessServersRequest): ListKeyAccessServersRequest.AsObject;
  static serializeBinaryToWriter(message: ListKeyAccessServersRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListKeyAccessServersRequest;
  static deserializeBinaryFromReader(message: ListKeyAccessServersRequest, reader: jspb.BinaryReader): ListKeyAccessServersRequest;
}

export namespace ListKeyAccessServersRequest {
  export type AsObject = {
  }
}

export class ListKeyAccessServersResponse extends jspb.Message {
  getKeyAccessServersList(): Array<policy_objects_pb.KeyAccessServer>;
  setKeyAccessServersList(value: Array<policy_objects_pb.KeyAccessServer>): ListKeyAccessServersResponse;
  clearKeyAccessServersList(): ListKeyAccessServersResponse;
  addKeyAccessServers(value?: policy_objects_pb.KeyAccessServer, index?: number): policy_objects_pb.KeyAccessServer;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListKeyAccessServersResponse.AsObject;
  static toObject(includeInstance: boolean, msg: ListKeyAccessServersResponse): ListKeyAccessServersResponse.AsObject;
  static serializeBinaryToWriter(message: ListKeyAccessServersResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListKeyAccessServersResponse;
  static deserializeBinaryFromReader(message: ListKeyAccessServersResponse, reader: jspb.BinaryReader): ListKeyAccessServersResponse;
}

export namespace ListKeyAccessServersResponse {
  export type AsObject = {
    keyAccessServersList: Array<policy_objects_pb.KeyAccessServer.AsObject>,
  }
}

export class CreateKeyAccessServerRequest extends jspb.Message {
  getUri(): string;
  setUri(value: string): CreateKeyAccessServerRequest;

  getPublicKey(): policy_objects_pb.PublicKey | undefined;
  setPublicKey(value?: policy_objects_pb.PublicKey): CreateKeyAccessServerRequest;
  hasPublicKey(): boolean;
  clearPublicKey(): CreateKeyAccessServerRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): CreateKeyAccessServerRequest;
  hasMetadata(): boolean;
  clearMetadata(): CreateKeyAccessServerRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateKeyAccessServerRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateKeyAccessServerRequest): CreateKeyAccessServerRequest.AsObject;
  static serializeBinaryToWriter(message: CreateKeyAccessServerRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateKeyAccessServerRequest;
  static deserializeBinaryFromReader(message: CreateKeyAccessServerRequest, reader: jspb.BinaryReader): CreateKeyAccessServerRequest;
}

export namespace CreateKeyAccessServerRequest {
  export type AsObject = {
    uri: string,
    publicKey?: policy_objects_pb.PublicKey.AsObject,
    metadata?: common_common_pb.MetadataMutable.AsObject,
  }
}

export class CreateKeyAccessServerResponse extends jspb.Message {
  getKeyAccessServer(): policy_objects_pb.KeyAccessServer | undefined;
  setKeyAccessServer(value?: policy_objects_pb.KeyAccessServer): CreateKeyAccessServerResponse;
  hasKeyAccessServer(): boolean;
  clearKeyAccessServer(): CreateKeyAccessServerResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateKeyAccessServerResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateKeyAccessServerResponse): CreateKeyAccessServerResponse.AsObject;
  static serializeBinaryToWriter(message: CreateKeyAccessServerResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateKeyAccessServerResponse;
  static deserializeBinaryFromReader(message: CreateKeyAccessServerResponse, reader: jspb.BinaryReader): CreateKeyAccessServerResponse;
}

export namespace CreateKeyAccessServerResponse {
  export type AsObject = {
    keyAccessServer?: policy_objects_pb.KeyAccessServer.AsObject,
  }
}

export class UpdateKeyAccessServerRequest extends jspb.Message {
  getId(): string;
  setId(value: string): UpdateKeyAccessServerRequest;

  getUri(): string;
  setUri(value: string): UpdateKeyAccessServerRequest;

  getPublicKey(): policy_objects_pb.PublicKey | undefined;
  setPublicKey(value?: policy_objects_pb.PublicKey): UpdateKeyAccessServerRequest;
  hasPublicKey(): boolean;
  clearPublicKey(): UpdateKeyAccessServerRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): UpdateKeyAccessServerRequest;
  hasMetadata(): boolean;
  clearMetadata(): UpdateKeyAccessServerRequest;

  getMetadataUpdateBehavior(): common_common_pb.MetadataUpdateEnum;
  setMetadataUpdateBehavior(value: common_common_pb.MetadataUpdateEnum): UpdateKeyAccessServerRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateKeyAccessServerRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateKeyAccessServerRequest): UpdateKeyAccessServerRequest.AsObject;
  static serializeBinaryToWriter(message: UpdateKeyAccessServerRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateKeyAccessServerRequest;
  static deserializeBinaryFromReader(message: UpdateKeyAccessServerRequest, reader: jspb.BinaryReader): UpdateKeyAccessServerRequest;
}

export namespace UpdateKeyAccessServerRequest {
  export type AsObject = {
    id: string,
    uri: string,
    publicKey?: policy_objects_pb.PublicKey.AsObject,
    metadata?: common_common_pb.MetadataMutable.AsObject,
    metadataUpdateBehavior: common_common_pb.MetadataUpdateEnum,
  }
}

export class UpdateKeyAccessServerResponse extends jspb.Message {
  getKeyAccessServer(): policy_objects_pb.KeyAccessServer | undefined;
  setKeyAccessServer(value?: policy_objects_pb.KeyAccessServer): UpdateKeyAccessServerResponse;
  hasKeyAccessServer(): boolean;
  clearKeyAccessServer(): UpdateKeyAccessServerResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateKeyAccessServerResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateKeyAccessServerResponse): UpdateKeyAccessServerResponse.AsObject;
  static serializeBinaryToWriter(message: UpdateKeyAccessServerResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateKeyAccessServerResponse;
  static deserializeBinaryFromReader(message: UpdateKeyAccessServerResponse, reader: jspb.BinaryReader): UpdateKeyAccessServerResponse;
}

export namespace UpdateKeyAccessServerResponse {
  export type AsObject = {
    keyAccessServer?: policy_objects_pb.KeyAccessServer.AsObject,
  }
}

export class DeleteKeyAccessServerRequest extends jspb.Message {
  getId(): string;
  setId(value: string): DeleteKeyAccessServerRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteKeyAccessServerRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DeleteKeyAccessServerRequest): DeleteKeyAccessServerRequest.AsObject;
  static serializeBinaryToWriter(message: DeleteKeyAccessServerRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeleteKeyAccessServerRequest;
  static deserializeBinaryFromReader(message: DeleteKeyAccessServerRequest, reader: jspb.BinaryReader): DeleteKeyAccessServerRequest;
}

export namespace DeleteKeyAccessServerRequest {
  export type AsObject = {
    id: string,
  }
}

export class DeleteKeyAccessServerResponse extends jspb.Message {
  getKeyAccessServer(): policy_objects_pb.KeyAccessServer | undefined;
  setKeyAccessServer(value?: policy_objects_pb.KeyAccessServer): DeleteKeyAccessServerResponse;
  hasKeyAccessServer(): boolean;
  clearKeyAccessServer(): DeleteKeyAccessServerResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteKeyAccessServerResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DeleteKeyAccessServerResponse): DeleteKeyAccessServerResponse.AsObject;
  static serializeBinaryToWriter(message: DeleteKeyAccessServerResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeleteKeyAccessServerResponse;
  static deserializeBinaryFromReader(message: DeleteKeyAccessServerResponse, reader: jspb.BinaryReader): DeleteKeyAccessServerResponse;
}

export namespace DeleteKeyAccessServerResponse {
  export type AsObject = {
    keyAccessServer?: policy_objects_pb.KeyAccessServer.AsObject,
  }
}

