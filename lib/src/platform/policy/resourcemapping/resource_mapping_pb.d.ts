import * as jspb from 'google-protobuf';

import * as buf_validate_validate_pb from '../../buf/validate/validate_pb'; // proto import: "buf/validate/validate.proto"
import * as google_api_annotations_pb from '../../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as common_common_pb from '../../common/common_pb'; // proto import: "common/common.proto"
import * as policy_objects_pb from '../../policy/objects_pb'; // proto import: "policy/objects.proto"

export class ListResourceMappingsRequest extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListResourceMappingsRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: ListResourceMappingsRequest
  ): ListResourceMappingsRequest.AsObject;
  static serializeBinaryToWriter(
    message: ListResourceMappingsRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): ListResourceMappingsRequest;
  static deserializeBinaryFromReader(
    message: ListResourceMappingsRequest,
    reader: jspb.BinaryReader
  ): ListResourceMappingsRequest;
}

export namespace ListResourceMappingsRequest {
  export type AsObject = {};
}

export class ListResourceMappingsResponse extends jspb.Message {
  getResourceMappingsList(): Array<policy_objects_pb.ResourceMapping>;
  setResourceMappingsList(
    value: Array<policy_objects_pb.ResourceMapping>
  ): ListResourceMappingsResponse;
  clearResourceMappingsList(): ListResourceMappingsResponse;
  addResourceMappings(
    value?: policy_objects_pb.ResourceMapping,
    index?: number
  ): policy_objects_pb.ResourceMapping;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListResourceMappingsResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: ListResourceMappingsResponse
  ): ListResourceMappingsResponse.AsObject;
  static serializeBinaryToWriter(
    message: ListResourceMappingsResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): ListResourceMappingsResponse;
  static deserializeBinaryFromReader(
    message: ListResourceMappingsResponse,
    reader: jspb.BinaryReader
  ): ListResourceMappingsResponse;
}

export namespace ListResourceMappingsResponse {
  export type AsObject = {
    resourceMappingsList: Array<policy_objects_pb.ResourceMapping.AsObject>;
  };
}

export class GetResourceMappingRequest extends jspb.Message {
  getId(): string;
  setId(value: string): GetResourceMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetResourceMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetResourceMappingRequest
  ): GetResourceMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: GetResourceMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetResourceMappingRequest;
  static deserializeBinaryFromReader(
    message: GetResourceMappingRequest,
    reader: jspb.BinaryReader
  ): GetResourceMappingRequest;
}

export namespace GetResourceMappingRequest {
  export type AsObject = {
    id: string;
  };
}

export class GetResourceMappingResponse extends jspb.Message {
  getResourceMapping(): policy_objects_pb.ResourceMapping | undefined;
  setResourceMapping(value?: policy_objects_pb.ResourceMapping): GetResourceMappingResponse;
  hasResourceMapping(): boolean;
  clearResourceMapping(): GetResourceMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetResourceMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetResourceMappingResponse
  ): GetResourceMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: GetResourceMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetResourceMappingResponse;
  static deserializeBinaryFromReader(
    message: GetResourceMappingResponse,
    reader: jspb.BinaryReader
  ): GetResourceMappingResponse;
}

export namespace GetResourceMappingResponse {
  export type AsObject = {
    resourceMapping?: policy_objects_pb.ResourceMapping.AsObject;
  };
}

export class CreateResourceMappingRequest extends jspb.Message {
  getAttributeValueId(): string;
  setAttributeValueId(value: string): CreateResourceMappingRequest;

  getTermsList(): Array<string>;
  setTermsList(value: Array<string>): CreateResourceMappingRequest;
  clearTermsList(): CreateResourceMappingRequest;
  addTerms(value: string, index?: number): CreateResourceMappingRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): CreateResourceMappingRequest;
  hasMetadata(): boolean;
  clearMetadata(): CreateResourceMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateResourceMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: CreateResourceMappingRequest
  ): CreateResourceMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: CreateResourceMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): CreateResourceMappingRequest;
  static deserializeBinaryFromReader(
    message: CreateResourceMappingRequest,
    reader: jspb.BinaryReader
  ): CreateResourceMappingRequest;
}

export namespace CreateResourceMappingRequest {
  export type AsObject = {
    attributeValueId: string;
    termsList: Array<string>;
    metadata?: common_common_pb.MetadataMutable.AsObject;
  };
}

export class CreateResourceMappingResponse extends jspb.Message {
  getResourceMapping(): policy_objects_pb.ResourceMapping | undefined;
  setResourceMapping(value?: policy_objects_pb.ResourceMapping): CreateResourceMappingResponse;
  hasResourceMapping(): boolean;
  clearResourceMapping(): CreateResourceMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateResourceMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: CreateResourceMappingResponse
  ): CreateResourceMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: CreateResourceMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): CreateResourceMappingResponse;
  static deserializeBinaryFromReader(
    message: CreateResourceMappingResponse,
    reader: jspb.BinaryReader
  ): CreateResourceMappingResponse;
}

export namespace CreateResourceMappingResponse {
  export type AsObject = {
    resourceMapping?: policy_objects_pb.ResourceMapping.AsObject;
  };
}

export class UpdateResourceMappingRequest extends jspb.Message {
  getId(): string;
  setId(value: string): UpdateResourceMappingRequest;

  getAttributeValueId(): string;
  setAttributeValueId(value: string): UpdateResourceMappingRequest;

  getTermsList(): Array<string>;
  setTermsList(value: Array<string>): UpdateResourceMappingRequest;
  clearTermsList(): UpdateResourceMappingRequest;
  addTerms(value: string, index?: number): UpdateResourceMappingRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): UpdateResourceMappingRequest;
  hasMetadata(): boolean;
  clearMetadata(): UpdateResourceMappingRequest;

  getMetadataUpdateBehavior(): common_common_pb.MetadataUpdateEnum;
  setMetadataUpdateBehavior(
    value: common_common_pb.MetadataUpdateEnum
  ): UpdateResourceMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateResourceMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: UpdateResourceMappingRequest
  ): UpdateResourceMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: UpdateResourceMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): UpdateResourceMappingRequest;
  static deserializeBinaryFromReader(
    message: UpdateResourceMappingRequest,
    reader: jspb.BinaryReader
  ): UpdateResourceMappingRequest;
}

export namespace UpdateResourceMappingRequest {
  export type AsObject = {
    id: string;
    attributeValueId: string;
    termsList: Array<string>;
    metadata?: common_common_pb.MetadataMutable.AsObject;
    metadataUpdateBehavior: common_common_pb.MetadataUpdateEnum;
  };
}

export class UpdateResourceMappingResponse extends jspb.Message {
  getResourceMapping(): policy_objects_pb.ResourceMapping | undefined;
  setResourceMapping(value?: policy_objects_pb.ResourceMapping): UpdateResourceMappingResponse;
  hasResourceMapping(): boolean;
  clearResourceMapping(): UpdateResourceMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateResourceMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: UpdateResourceMappingResponse
  ): UpdateResourceMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: UpdateResourceMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): UpdateResourceMappingResponse;
  static deserializeBinaryFromReader(
    message: UpdateResourceMappingResponse,
    reader: jspb.BinaryReader
  ): UpdateResourceMappingResponse;
}

export namespace UpdateResourceMappingResponse {
  export type AsObject = {
    resourceMapping?: policy_objects_pb.ResourceMapping.AsObject;
  };
}

export class DeleteResourceMappingRequest extends jspb.Message {
  getId(): string;
  setId(value: string): DeleteResourceMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteResourceMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: DeleteResourceMappingRequest
  ): DeleteResourceMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: DeleteResourceMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): DeleteResourceMappingRequest;
  static deserializeBinaryFromReader(
    message: DeleteResourceMappingRequest,
    reader: jspb.BinaryReader
  ): DeleteResourceMappingRequest;
}

export namespace DeleteResourceMappingRequest {
  export type AsObject = {
    id: string;
  };
}

export class DeleteResourceMappingResponse extends jspb.Message {
  getResourceMapping(): policy_objects_pb.ResourceMapping | undefined;
  setResourceMapping(value?: policy_objects_pb.ResourceMapping): DeleteResourceMappingResponse;
  hasResourceMapping(): boolean;
  clearResourceMapping(): DeleteResourceMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteResourceMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: DeleteResourceMappingResponse
  ): DeleteResourceMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: DeleteResourceMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): DeleteResourceMappingResponse;
  static deserializeBinaryFromReader(
    message: DeleteResourceMappingResponse,
    reader: jspb.BinaryReader
  ): DeleteResourceMappingResponse;
}

export namespace DeleteResourceMappingResponse {
  export type AsObject = {
    resourceMapping?: policy_objects_pb.ResourceMapping.AsObject;
  };
}
