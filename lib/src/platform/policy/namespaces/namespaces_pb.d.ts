import * as jspb from 'google-protobuf'

import * as buf_validate_validate_pb from '../../buf/validate/validate_pb'; // proto import: "buf/validate/validate.proto"
import * as google_api_annotations_pb from '../../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as common_common_pb from '../../common/common_pb'; // proto import: "common/common.proto"
import * as policy_objects_pb from '../../policy/objects_pb'; // proto import: "policy/objects.proto"


export class GetNamespaceRequest extends jspb.Message {
  getId(): string;
  setId(value: string): GetNamespaceRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetNamespaceRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetNamespaceRequest): GetNamespaceRequest.AsObject;
  static serializeBinaryToWriter(message: GetNamespaceRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetNamespaceRequest;
  static deserializeBinaryFromReader(message: GetNamespaceRequest, reader: jspb.BinaryReader): GetNamespaceRequest;
}

export namespace GetNamespaceRequest {
  export type AsObject = {
    id: string,
  }
}

export class GetNamespaceResponse extends jspb.Message {
  getNamespace(): policy_objects_pb.Namespace | undefined;
  setNamespace(value?: policy_objects_pb.Namespace): GetNamespaceResponse;
  hasNamespace(): boolean;
  clearNamespace(): GetNamespaceResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetNamespaceResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetNamespaceResponse): GetNamespaceResponse.AsObject;
  static serializeBinaryToWriter(message: GetNamespaceResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetNamespaceResponse;
  static deserializeBinaryFromReader(message: GetNamespaceResponse, reader: jspb.BinaryReader): GetNamespaceResponse;
}

export namespace GetNamespaceResponse {
  export type AsObject = {
    namespace?: policy_objects_pb.Namespace.AsObject,
  }
}

export class ListNamespacesRequest extends jspb.Message {
  getState(): common_common_pb.ActiveStateEnum;
  setState(value: common_common_pb.ActiveStateEnum): ListNamespacesRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListNamespacesRequest.AsObject;
  static toObject(includeInstance: boolean, msg: ListNamespacesRequest): ListNamespacesRequest.AsObject;
  static serializeBinaryToWriter(message: ListNamespacesRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListNamespacesRequest;
  static deserializeBinaryFromReader(message: ListNamespacesRequest, reader: jspb.BinaryReader): ListNamespacesRequest;
}

export namespace ListNamespacesRequest {
  export type AsObject = {
    state: common_common_pb.ActiveStateEnum,
  }
}

export class ListNamespacesResponse extends jspb.Message {
  getNamespacesList(): Array<policy_objects_pb.Namespace>;
  setNamespacesList(value: Array<policy_objects_pb.Namespace>): ListNamespacesResponse;
  clearNamespacesList(): ListNamespacesResponse;
  addNamespaces(value?: policy_objects_pb.Namespace, index?: number): policy_objects_pb.Namespace;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListNamespacesResponse.AsObject;
  static toObject(includeInstance: boolean, msg: ListNamespacesResponse): ListNamespacesResponse.AsObject;
  static serializeBinaryToWriter(message: ListNamespacesResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListNamespacesResponse;
  static deserializeBinaryFromReader(message: ListNamespacesResponse, reader: jspb.BinaryReader): ListNamespacesResponse;
}

export namespace ListNamespacesResponse {
  export type AsObject = {
    namespacesList: Array<policy_objects_pb.Namespace.AsObject>,
  }
}

export class CreateNamespaceRequest extends jspb.Message {
  getName(): string;
  setName(value: string): CreateNamespaceRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): CreateNamespaceRequest;
  hasMetadata(): boolean;
  clearMetadata(): CreateNamespaceRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateNamespaceRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateNamespaceRequest): CreateNamespaceRequest.AsObject;
  static serializeBinaryToWriter(message: CreateNamespaceRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateNamespaceRequest;
  static deserializeBinaryFromReader(message: CreateNamespaceRequest, reader: jspb.BinaryReader): CreateNamespaceRequest;
}

export namespace CreateNamespaceRequest {
  export type AsObject = {
    name: string,
    metadata?: common_common_pb.MetadataMutable.AsObject,
  }
}

export class CreateNamespaceResponse extends jspb.Message {
  getNamespace(): policy_objects_pb.Namespace | undefined;
  setNamespace(value?: policy_objects_pb.Namespace): CreateNamespaceResponse;
  hasNamespace(): boolean;
  clearNamespace(): CreateNamespaceResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateNamespaceResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateNamespaceResponse): CreateNamespaceResponse.AsObject;
  static serializeBinaryToWriter(message: CreateNamespaceResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateNamespaceResponse;
  static deserializeBinaryFromReader(message: CreateNamespaceResponse, reader: jspb.BinaryReader): CreateNamespaceResponse;
}

export namespace CreateNamespaceResponse {
  export type AsObject = {
    namespace?: policy_objects_pb.Namespace.AsObject,
  }
}

export class UpdateNamespaceRequest extends jspb.Message {
  getId(): string;
  setId(value: string): UpdateNamespaceRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): UpdateNamespaceRequest;
  hasMetadata(): boolean;
  clearMetadata(): UpdateNamespaceRequest;

  getMetadataUpdateBehavior(): common_common_pb.MetadataUpdateEnum;
  setMetadataUpdateBehavior(value: common_common_pb.MetadataUpdateEnum): UpdateNamespaceRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateNamespaceRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateNamespaceRequest): UpdateNamespaceRequest.AsObject;
  static serializeBinaryToWriter(message: UpdateNamespaceRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateNamespaceRequest;
  static deserializeBinaryFromReader(message: UpdateNamespaceRequest, reader: jspb.BinaryReader): UpdateNamespaceRequest;
}

export namespace UpdateNamespaceRequest {
  export type AsObject = {
    id: string,
    metadata?: common_common_pb.MetadataMutable.AsObject,
    metadataUpdateBehavior: common_common_pb.MetadataUpdateEnum,
  }
}

export class UpdateNamespaceResponse extends jspb.Message {
  getNamespace(): policy_objects_pb.Namespace | undefined;
  setNamespace(value?: policy_objects_pb.Namespace): UpdateNamespaceResponse;
  hasNamespace(): boolean;
  clearNamespace(): UpdateNamespaceResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateNamespaceResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateNamespaceResponse): UpdateNamespaceResponse.AsObject;
  static serializeBinaryToWriter(message: UpdateNamespaceResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateNamespaceResponse;
  static deserializeBinaryFromReader(message: UpdateNamespaceResponse, reader: jspb.BinaryReader): UpdateNamespaceResponse;
}

export namespace UpdateNamespaceResponse {
  export type AsObject = {
    namespace?: policy_objects_pb.Namespace.AsObject,
  }
}

export class DeactivateNamespaceRequest extends jspb.Message {
  getId(): string;
  setId(value: string): DeactivateNamespaceRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeactivateNamespaceRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DeactivateNamespaceRequest): DeactivateNamespaceRequest.AsObject;
  static serializeBinaryToWriter(message: DeactivateNamespaceRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeactivateNamespaceRequest;
  static deserializeBinaryFromReader(message: DeactivateNamespaceRequest, reader: jspb.BinaryReader): DeactivateNamespaceRequest;
}

export namespace DeactivateNamespaceRequest {
  export type AsObject = {
    id: string,
  }
}

export class DeactivateNamespaceResponse extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeactivateNamespaceResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DeactivateNamespaceResponse): DeactivateNamespaceResponse.AsObject;
  static serializeBinaryToWriter(message: DeactivateNamespaceResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeactivateNamespaceResponse;
  static deserializeBinaryFromReader(message: DeactivateNamespaceResponse, reader: jspb.BinaryReader): DeactivateNamespaceResponse;
}

export namespace DeactivateNamespaceResponse {
  export type AsObject = {
  }
}

