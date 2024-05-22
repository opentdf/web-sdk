import * as jspb from 'google-protobuf';

import * as buf_validate_validate_pb from '../../buf/validate/validate_pb'; // proto import: "buf/validate/validate.proto"
import * as google_api_annotations_pb from '../../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as common_common_pb from '../../common/common_pb'; // proto import: "common/common.proto"
import * as policy_objects_pb from '../../policy/objects_pb'; // proto import: "policy/objects.proto"

export class MatchSubjectMappingsRequest extends jspb.Message {
  getSubjectPropertiesList(): Array<policy_objects_pb.SubjectProperty>;
  setSubjectPropertiesList(
    value: Array<policy_objects_pb.SubjectProperty>
  ): MatchSubjectMappingsRequest;
  clearSubjectPropertiesList(): MatchSubjectMappingsRequest;
  addSubjectProperties(
    value?: policy_objects_pb.SubjectProperty,
    index?: number
  ): policy_objects_pb.SubjectProperty;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): MatchSubjectMappingsRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: MatchSubjectMappingsRequest
  ): MatchSubjectMappingsRequest.AsObject;
  static serializeBinaryToWriter(
    message: MatchSubjectMappingsRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): MatchSubjectMappingsRequest;
  static deserializeBinaryFromReader(
    message: MatchSubjectMappingsRequest,
    reader: jspb.BinaryReader
  ): MatchSubjectMappingsRequest;
}

export namespace MatchSubjectMappingsRequest {
  export type AsObject = {
    subjectPropertiesList: Array<policy_objects_pb.SubjectProperty.AsObject>;
  };
}

export class MatchSubjectMappingsResponse extends jspb.Message {
  getSubjectMappingsList(): Array<policy_objects_pb.SubjectMapping>;
  setSubjectMappingsList(
    value: Array<policy_objects_pb.SubjectMapping>
  ): MatchSubjectMappingsResponse;
  clearSubjectMappingsList(): MatchSubjectMappingsResponse;
  addSubjectMappings(
    value?: policy_objects_pb.SubjectMapping,
    index?: number
  ): policy_objects_pb.SubjectMapping;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): MatchSubjectMappingsResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: MatchSubjectMappingsResponse
  ): MatchSubjectMappingsResponse.AsObject;
  static serializeBinaryToWriter(
    message: MatchSubjectMappingsResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): MatchSubjectMappingsResponse;
  static deserializeBinaryFromReader(
    message: MatchSubjectMappingsResponse,
    reader: jspb.BinaryReader
  ): MatchSubjectMappingsResponse;
}

export namespace MatchSubjectMappingsResponse {
  export type AsObject = {
    subjectMappingsList: Array<policy_objects_pb.SubjectMapping.AsObject>;
  };
}

export class GetSubjectMappingRequest extends jspb.Message {
  getId(): string;
  setId(value: string): GetSubjectMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetSubjectMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetSubjectMappingRequest
  ): GetSubjectMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: GetSubjectMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetSubjectMappingRequest;
  static deserializeBinaryFromReader(
    message: GetSubjectMappingRequest,
    reader: jspb.BinaryReader
  ): GetSubjectMappingRequest;
}

export namespace GetSubjectMappingRequest {
  export type AsObject = {
    id: string;
  };
}

export class GetSubjectMappingResponse extends jspb.Message {
  getSubjectMapping(): policy_objects_pb.SubjectMapping | undefined;
  setSubjectMapping(value?: policy_objects_pb.SubjectMapping): GetSubjectMappingResponse;
  hasSubjectMapping(): boolean;
  clearSubjectMapping(): GetSubjectMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetSubjectMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetSubjectMappingResponse
  ): GetSubjectMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: GetSubjectMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetSubjectMappingResponse;
  static deserializeBinaryFromReader(
    message: GetSubjectMappingResponse,
    reader: jspb.BinaryReader
  ): GetSubjectMappingResponse;
}

export namespace GetSubjectMappingResponse {
  export type AsObject = {
    subjectMapping?: policy_objects_pb.SubjectMapping.AsObject;
  };
}

export class ListSubjectMappingsRequest extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListSubjectMappingsRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: ListSubjectMappingsRequest
  ): ListSubjectMappingsRequest.AsObject;
  static serializeBinaryToWriter(
    message: ListSubjectMappingsRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): ListSubjectMappingsRequest;
  static deserializeBinaryFromReader(
    message: ListSubjectMappingsRequest,
    reader: jspb.BinaryReader
  ): ListSubjectMappingsRequest;
}

export namespace ListSubjectMappingsRequest {
  export type AsObject = {};
}

export class ListSubjectMappingsResponse extends jspb.Message {
  getSubjectMappingsList(): Array<policy_objects_pb.SubjectMapping>;
  setSubjectMappingsList(
    value: Array<policy_objects_pb.SubjectMapping>
  ): ListSubjectMappingsResponse;
  clearSubjectMappingsList(): ListSubjectMappingsResponse;
  addSubjectMappings(
    value?: policy_objects_pb.SubjectMapping,
    index?: number
  ): policy_objects_pb.SubjectMapping;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListSubjectMappingsResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: ListSubjectMappingsResponse
  ): ListSubjectMappingsResponse.AsObject;
  static serializeBinaryToWriter(
    message: ListSubjectMappingsResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): ListSubjectMappingsResponse;
  static deserializeBinaryFromReader(
    message: ListSubjectMappingsResponse,
    reader: jspb.BinaryReader
  ): ListSubjectMappingsResponse;
}

export namespace ListSubjectMappingsResponse {
  export type AsObject = {
    subjectMappingsList: Array<policy_objects_pb.SubjectMapping.AsObject>;
  };
}

export class CreateSubjectMappingRequest extends jspb.Message {
  getAttributeValueId(): string;
  setAttributeValueId(value: string): CreateSubjectMappingRequest;

  getActionsList(): Array<policy_objects_pb.Action>;
  setActionsList(value: Array<policy_objects_pb.Action>): CreateSubjectMappingRequest;
  clearActionsList(): CreateSubjectMappingRequest;
  addActions(value?: policy_objects_pb.Action, index?: number): policy_objects_pb.Action;

  getExistingSubjectConditionSetId(): string;
  setExistingSubjectConditionSetId(value: string): CreateSubjectMappingRequest;

  getNewSubjectConditionSet(): SubjectConditionSetCreate | undefined;
  setNewSubjectConditionSet(value?: SubjectConditionSetCreate): CreateSubjectMappingRequest;
  hasNewSubjectConditionSet(): boolean;
  clearNewSubjectConditionSet(): CreateSubjectMappingRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): CreateSubjectMappingRequest;
  hasMetadata(): boolean;
  clearMetadata(): CreateSubjectMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateSubjectMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: CreateSubjectMappingRequest
  ): CreateSubjectMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: CreateSubjectMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): CreateSubjectMappingRequest;
  static deserializeBinaryFromReader(
    message: CreateSubjectMappingRequest,
    reader: jspb.BinaryReader
  ): CreateSubjectMappingRequest;
}

export namespace CreateSubjectMappingRequest {
  export type AsObject = {
    attributeValueId: string;
    actionsList: Array<policy_objects_pb.Action.AsObject>;
    existingSubjectConditionSetId: string;
    newSubjectConditionSet?: SubjectConditionSetCreate.AsObject;
    metadata?: common_common_pb.MetadataMutable.AsObject;
  };
}

export class CreateSubjectMappingResponse extends jspb.Message {
  getSubjectMapping(): policy_objects_pb.SubjectMapping | undefined;
  setSubjectMapping(value?: policy_objects_pb.SubjectMapping): CreateSubjectMappingResponse;
  hasSubjectMapping(): boolean;
  clearSubjectMapping(): CreateSubjectMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateSubjectMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: CreateSubjectMappingResponse
  ): CreateSubjectMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: CreateSubjectMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): CreateSubjectMappingResponse;
  static deserializeBinaryFromReader(
    message: CreateSubjectMappingResponse,
    reader: jspb.BinaryReader
  ): CreateSubjectMappingResponse;
}

export namespace CreateSubjectMappingResponse {
  export type AsObject = {
    subjectMapping?: policy_objects_pb.SubjectMapping.AsObject;
  };
}

export class UpdateSubjectMappingRequest extends jspb.Message {
  getId(): string;
  setId(value: string): UpdateSubjectMappingRequest;

  getSubjectConditionSetId(): string;
  setSubjectConditionSetId(value: string): UpdateSubjectMappingRequest;

  getActionsList(): Array<policy_objects_pb.Action>;
  setActionsList(value: Array<policy_objects_pb.Action>): UpdateSubjectMappingRequest;
  clearActionsList(): UpdateSubjectMappingRequest;
  addActions(value?: policy_objects_pb.Action, index?: number): policy_objects_pb.Action;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): UpdateSubjectMappingRequest;
  hasMetadata(): boolean;
  clearMetadata(): UpdateSubjectMappingRequest;

  getMetadataUpdateBehavior(): common_common_pb.MetadataUpdateEnum;
  setMetadataUpdateBehavior(
    value: common_common_pb.MetadataUpdateEnum
  ): UpdateSubjectMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateSubjectMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: UpdateSubjectMappingRequest
  ): UpdateSubjectMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: UpdateSubjectMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): UpdateSubjectMappingRequest;
  static deserializeBinaryFromReader(
    message: UpdateSubjectMappingRequest,
    reader: jspb.BinaryReader
  ): UpdateSubjectMappingRequest;
}

export namespace UpdateSubjectMappingRequest {
  export type AsObject = {
    id: string;
    subjectConditionSetId: string;
    actionsList: Array<policy_objects_pb.Action.AsObject>;
    metadata?: common_common_pb.MetadataMutable.AsObject;
    metadataUpdateBehavior: common_common_pb.MetadataUpdateEnum;
  };
}

export class UpdateSubjectMappingResponse extends jspb.Message {
  getSubjectMapping(): policy_objects_pb.SubjectMapping | undefined;
  setSubjectMapping(value?: policy_objects_pb.SubjectMapping): UpdateSubjectMappingResponse;
  hasSubjectMapping(): boolean;
  clearSubjectMapping(): UpdateSubjectMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateSubjectMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: UpdateSubjectMappingResponse
  ): UpdateSubjectMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: UpdateSubjectMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): UpdateSubjectMappingResponse;
  static deserializeBinaryFromReader(
    message: UpdateSubjectMappingResponse,
    reader: jspb.BinaryReader
  ): UpdateSubjectMappingResponse;
}

export namespace UpdateSubjectMappingResponse {
  export type AsObject = {
    subjectMapping?: policy_objects_pb.SubjectMapping.AsObject;
  };
}

export class DeleteSubjectMappingRequest extends jspb.Message {
  getId(): string;
  setId(value: string): DeleteSubjectMappingRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteSubjectMappingRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: DeleteSubjectMappingRequest
  ): DeleteSubjectMappingRequest.AsObject;
  static serializeBinaryToWriter(
    message: DeleteSubjectMappingRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): DeleteSubjectMappingRequest;
  static deserializeBinaryFromReader(
    message: DeleteSubjectMappingRequest,
    reader: jspb.BinaryReader
  ): DeleteSubjectMappingRequest;
}

export namespace DeleteSubjectMappingRequest {
  export type AsObject = {
    id: string;
  };
}

export class DeleteSubjectMappingResponse extends jspb.Message {
  getSubjectMapping(): policy_objects_pb.SubjectMapping | undefined;
  setSubjectMapping(value?: policy_objects_pb.SubjectMapping): DeleteSubjectMappingResponse;
  hasSubjectMapping(): boolean;
  clearSubjectMapping(): DeleteSubjectMappingResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteSubjectMappingResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: DeleteSubjectMappingResponse
  ): DeleteSubjectMappingResponse.AsObject;
  static serializeBinaryToWriter(
    message: DeleteSubjectMappingResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): DeleteSubjectMappingResponse;
  static deserializeBinaryFromReader(
    message: DeleteSubjectMappingResponse,
    reader: jspb.BinaryReader
  ): DeleteSubjectMappingResponse;
}

export namespace DeleteSubjectMappingResponse {
  export type AsObject = {
    subjectMapping?: policy_objects_pb.SubjectMapping.AsObject;
  };
}

export class GetSubjectConditionSetRequest extends jspb.Message {
  getId(): string;
  setId(value: string): GetSubjectConditionSetRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetSubjectConditionSetRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetSubjectConditionSetRequest
  ): GetSubjectConditionSetRequest.AsObject;
  static serializeBinaryToWriter(
    message: GetSubjectConditionSetRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetSubjectConditionSetRequest;
  static deserializeBinaryFromReader(
    message: GetSubjectConditionSetRequest,
    reader: jspb.BinaryReader
  ): GetSubjectConditionSetRequest;
}

export namespace GetSubjectConditionSetRequest {
  export type AsObject = {
    id: string;
  };
}

export class GetSubjectConditionSetResponse extends jspb.Message {
  getSubjectConditionSet(): policy_objects_pb.SubjectConditionSet | undefined;
  setSubjectConditionSet(
    value?: policy_objects_pb.SubjectConditionSet
  ): GetSubjectConditionSetResponse;
  hasSubjectConditionSet(): boolean;
  clearSubjectConditionSet(): GetSubjectConditionSetResponse;

  getAssociatedSubjectMappingsList(): Array<policy_objects_pb.SubjectMapping>;
  setAssociatedSubjectMappingsList(
    value: Array<policy_objects_pb.SubjectMapping>
  ): GetSubjectConditionSetResponse;
  clearAssociatedSubjectMappingsList(): GetSubjectConditionSetResponse;
  addAssociatedSubjectMappings(
    value?: policy_objects_pb.SubjectMapping,
    index?: number
  ): policy_objects_pb.SubjectMapping;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetSubjectConditionSetResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetSubjectConditionSetResponse
  ): GetSubjectConditionSetResponse.AsObject;
  static serializeBinaryToWriter(
    message: GetSubjectConditionSetResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetSubjectConditionSetResponse;
  static deserializeBinaryFromReader(
    message: GetSubjectConditionSetResponse,
    reader: jspb.BinaryReader
  ): GetSubjectConditionSetResponse;
}

export namespace GetSubjectConditionSetResponse {
  export type AsObject = {
    subjectConditionSet?: policy_objects_pb.SubjectConditionSet.AsObject;
    associatedSubjectMappingsList: Array<policy_objects_pb.SubjectMapping.AsObject>;
  };
}

export class ListSubjectConditionSetsRequest extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListSubjectConditionSetsRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: ListSubjectConditionSetsRequest
  ): ListSubjectConditionSetsRequest.AsObject;
  static serializeBinaryToWriter(
    message: ListSubjectConditionSetsRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): ListSubjectConditionSetsRequest;
  static deserializeBinaryFromReader(
    message: ListSubjectConditionSetsRequest,
    reader: jspb.BinaryReader
  ): ListSubjectConditionSetsRequest;
}

export namespace ListSubjectConditionSetsRequest {
  export type AsObject = {};
}

export class ListSubjectConditionSetsResponse extends jspb.Message {
  getSubjectConditionSetsList(): Array<policy_objects_pb.SubjectConditionSet>;
  setSubjectConditionSetsList(
    value: Array<policy_objects_pb.SubjectConditionSet>
  ): ListSubjectConditionSetsResponse;
  clearSubjectConditionSetsList(): ListSubjectConditionSetsResponse;
  addSubjectConditionSets(
    value?: policy_objects_pb.SubjectConditionSet,
    index?: number
  ): policy_objects_pb.SubjectConditionSet;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListSubjectConditionSetsResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: ListSubjectConditionSetsResponse
  ): ListSubjectConditionSetsResponse.AsObject;
  static serializeBinaryToWriter(
    message: ListSubjectConditionSetsResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): ListSubjectConditionSetsResponse;
  static deserializeBinaryFromReader(
    message: ListSubjectConditionSetsResponse,
    reader: jspb.BinaryReader
  ): ListSubjectConditionSetsResponse;
}

export namespace ListSubjectConditionSetsResponse {
  export type AsObject = {
    subjectConditionSetsList: Array<policy_objects_pb.SubjectConditionSet.AsObject>;
  };
}

export class SubjectConditionSetCreate extends jspb.Message {
  getSubjectSetsList(): Array<policy_objects_pb.SubjectSet>;
  setSubjectSetsList(value: Array<policy_objects_pb.SubjectSet>): SubjectConditionSetCreate;
  clearSubjectSetsList(): SubjectConditionSetCreate;
  addSubjectSets(
    value?: policy_objects_pb.SubjectSet,
    index?: number
  ): policy_objects_pb.SubjectSet;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): SubjectConditionSetCreate;
  hasMetadata(): boolean;
  clearMetadata(): SubjectConditionSetCreate;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): SubjectConditionSetCreate.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: SubjectConditionSetCreate
  ): SubjectConditionSetCreate.AsObject;
  static serializeBinaryToWriter(
    message: SubjectConditionSetCreate,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): SubjectConditionSetCreate;
  static deserializeBinaryFromReader(
    message: SubjectConditionSetCreate,
    reader: jspb.BinaryReader
  ): SubjectConditionSetCreate;
}

export namespace SubjectConditionSetCreate {
  export type AsObject = {
    subjectSetsList: Array<policy_objects_pb.SubjectSet.AsObject>;
    metadata?: common_common_pb.MetadataMutable.AsObject;
  };
}

export class CreateSubjectConditionSetRequest extends jspb.Message {
  getSubjectConditionSet(): SubjectConditionSetCreate | undefined;
  setSubjectConditionSet(value?: SubjectConditionSetCreate): CreateSubjectConditionSetRequest;
  hasSubjectConditionSet(): boolean;
  clearSubjectConditionSet(): CreateSubjectConditionSetRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateSubjectConditionSetRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: CreateSubjectConditionSetRequest
  ): CreateSubjectConditionSetRequest.AsObject;
  static serializeBinaryToWriter(
    message: CreateSubjectConditionSetRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): CreateSubjectConditionSetRequest;
  static deserializeBinaryFromReader(
    message: CreateSubjectConditionSetRequest,
    reader: jspb.BinaryReader
  ): CreateSubjectConditionSetRequest;
}

export namespace CreateSubjectConditionSetRequest {
  export type AsObject = {
    subjectConditionSet?: SubjectConditionSetCreate.AsObject;
  };
}

export class CreateSubjectConditionSetResponse extends jspb.Message {
  getSubjectConditionSet(): policy_objects_pb.SubjectConditionSet | undefined;
  setSubjectConditionSet(
    value?: policy_objects_pb.SubjectConditionSet
  ): CreateSubjectConditionSetResponse;
  hasSubjectConditionSet(): boolean;
  clearSubjectConditionSet(): CreateSubjectConditionSetResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateSubjectConditionSetResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: CreateSubjectConditionSetResponse
  ): CreateSubjectConditionSetResponse.AsObject;
  static serializeBinaryToWriter(
    message: CreateSubjectConditionSetResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): CreateSubjectConditionSetResponse;
  static deserializeBinaryFromReader(
    message: CreateSubjectConditionSetResponse,
    reader: jspb.BinaryReader
  ): CreateSubjectConditionSetResponse;
}

export namespace CreateSubjectConditionSetResponse {
  export type AsObject = {
    subjectConditionSet?: policy_objects_pb.SubjectConditionSet.AsObject;
  };
}

export class UpdateSubjectConditionSetRequest extends jspb.Message {
  getId(): string;
  setId(value: string): UpdateSubjectConditionSetRequest;

  getSubjectSetsList(): Array<policy_objects_pb.SubjectSet>;
  setSubjectSetsList(value: Array<policy_objects_pb.SubjectSet>): UpdateSubjectConditionSetRequest;
  clearSubjectSetsList(): UpdateSubjectConditionSetRequest;
  addSubjectSets(
    value?: policy_objects_pb.SubjectSet,
    index?: number
  ): policy_objects_pb.SubjectSet;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): UpdateSubjectConditionSetRequest;
  hasMetadata(): boolean;
  clearMetadata(): UpdateSubjectConditionSetRequest;

  getMetadataUpdateBehavior(): common_common_pb.MetadataUpdateEnum;
  setMetadataUpdateBehavior(
    value: common_common_pb.MetadataUpdateEnum
  ): UpdateSubjectConditionSetRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateSubjectConditionSetRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: UpdateSubjectConditionSetRequest
  ): UpdateSubjectConditionSetRequest.AsObject;
  static serializeBinaryToWriter(
    message: UpdateSubjectConditionSetRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): UpdateSubjectConditionSetRequest;
  static deserializeBinaryFromReader(
    message: UpdateSubjectConditionSetRequest,
    reader: jspb.BinaryReader
  ): UpdateSubjectConditionSetRequest;
}

export namespace UpdateSubjectConditionSetRequest {
  export type AsObject = {
    id: string;
    subjectSetsList: Array<policy_objects_pb.SubjectSet.AsObject>;
    metadata?: common_common_pb.MetadataMutable.AsObject;
    metadataUpdateBehavior: common_common_pb.MetadataUpdateEnum;
  };
}

export class UpdateSubjectConditionSetResponse extends jspb.Message {
  getSubjectConditionSet(): policy_objects_pb.SubjectConditionSet | undefined;
  setSubjectConditionSet(
    value?: policy_objects_pb.SubjectConditionSet
  ): UpdateSubjectConditionSetResponse;
  hasSubjectConditionSet(): boolean;
  clearSubjectConditionSet(): UpdateSubjectConditionSetResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateSubjectConditionSetResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: UpdateSubjectConditionSetResponse
  ): UpdateSubjectConditionSetResponse.AsObject;
  static serializeBinaryToWriter(
    message: UpdateSubjectConditionSetResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): UpdateSubjectConditionSetResponse;
  static deserializeBinaryFromReader(
    message: UpdateSubjectConditionSetResponse,
    reader: jspb.BinaryReader
  ): UpdateSubjectConditionSetResponse;
}

export namespace UpdateSubjectConditionSetResponse {
  export type AsObject = {
    subjectConditionSet?: policy_objects_pb.SubjectConditionSet.AsObject;
  };
}

export class DeleteSubjectConditionSetRequest extends jspb.Message {
  getId(): string;
  setId(value: string): DeleteSubjectConditionSetRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteSubjectConditionSetRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: DeleteSubjectConditionSetRequest
  ): DeleteSubjectConditionSetRequest.AsObject;
  static serializeBinaryToWriter(
    message: DeleteSubjectConditionSetRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): DeleteSubjectConditionSetRequest;
  static deserializeBinaryFromReader(
    message: DeleteSubjectConditionSetRequest,
    reader: jspb.BinaryReader
  ): DeleteSubjectConditionSetRequest;
}

export namespace DeleteSubjectConditionSetRequest {
  export type AsObject = {
    id: string;
  };
}

export class DeleteSubjectConditionSetResponse extends jspb.Message {
  getSubjectConditionSet(): policy_objects_pb.SubjectConditionSet | undefined;
  setSubjectConditionSet(
    value?: policy_objects_pb.SubjectConditionSet
  ): DeleteSubjectConditionSetResponse;
  hasSubjectConditionSet(): boolean;
  clearSubjectConditionSet(): DeleteSubjectConditionSetResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteSubjectConditionSetResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: DeleteSubjectConditionSetResponse
  ): DeleteSubjectConditionSetResponse.AsObject;
  static serializeBinaryToWriter(
    message: DeleteSubjectConditionSetResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): DeleteSubjectConditionSetResponse;
  static deserializeBinaryFromReader(
    message: DeleteSubjectConditionSetResponse,
    reader: jspb.BinaryReader
  ): DeleteSubjectConditionSetResponse;
}

export namespace DeleteSubjectConditionSetResponse {
  export type AsObject = {
    subjectConditionSet?: policy_objects_pb.SubjectConditionSet.AsObject;
  };
}
