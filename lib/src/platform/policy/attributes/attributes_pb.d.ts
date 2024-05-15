import * as jspb from 'google-protobuf'

import * as buf_validate_validate_pb from '../../buf/validate/validate_pb'; // proto import: "buf/validate/validate.proto"
import * as common_common_pb from '../../common/common_pb'; // proto import: "common/common.proto"
import * as google_api_annotations_pb from '../../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as policy_objects_pb from '../../policy/objects_pb'; // proto import: "policy/objects.proto"
import * as policy_selectors_pb from '../../policy/selectors_pb'; // proto import: "policy/selectors.proto"


export class AttributeKeyAccessServer extends jspb.Message {
  getAttributeId(): string;
  setAttributeId(value: string): AttributeKeyAccessServer;

  getKeyAccessServerId(): string;
  setKeyAccessServerId(value: string): AttributeKeyAccessServer;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AttributeKeyAccessServer.AsObject;
  static toObject(includeInstance: boolean, msg: AttributeKeyAccessServer): AttributeKeyAccessServer.AsObject;
  static serializeBinaryToWriter(message: AttributeKeyAccessServer, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AttributeKeyAccessServer;
  static deserializeBinaryFromReader(message: AttributeKeyAccessServer, reader: jspb.BinaryReader): AttributeKeyAccessServer;
}

export namespace AttributeKeyAccessServer {
  export type AsObject = {
    attributeId: string,
    keyAccessServerId: string,
  }
}

export class ValueKeyAccessServer extends jspb.Message {
  getValueId(): string;
  setValueId(value: string): ValueKeyAccessServer;

  getKeyAccessServerId(): string;
  setKeyAccessServerId(value: string): ValueKeyAccessServer;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ValueKeyAccessServer.AsObject;
  static toObject(includeInstance: boolean, msg: ValueKeyAccessServer): ValueKeyAccessServer.AsObject;
  static serializeBinaryToWriter(message: ValueKeyAccessServer, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ValueKeyAccessServer;
  static deserializeBinaryFromReader(message: ValueKeyAccessServer, reader: jspb.BinaryReader): ValueKeyAccessServer;
}

export namespace ValueKeyAccessServer {
  export type AsObject = {
    valueId: string,
    keyAccessServerId: string,
  }
}

export class ListAttributesRequest extends jspb.Message {
  getState(): common_common_pb.ActiveStateEnum;
  setState(value: common_common_pb.ActiveStateEnum): ListAttributesRequest;

  getNamespace(): string;
  setNamespace(value: string): ListAttributesRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListAttributesRequest.AsObject;
  static toObject(includeInstance: boolean, msg: ListAttributesRequest): ListAttributesRequest.AsObject;
  static serializeBinaryToWriter(message: ListAttributesRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListAttributesRequest;
  static deserializeBinaryFromReader(message: ListAttributesRequest, reader: jspb.BinaryReader): ListAttributesRequest;
}

export namespace ListAttributesRequest {
  export type AsObject = {
    state: common_common_pb.ActiveStateEnum,
    namespace: string,
  }
}

export class ListAttributesResponse extends jspb.Message {
  getAttributesList(): Array<policy_objects_pb.Attribute>;
  setAttributesList(value: Array<policy_objects_pb.Attribute>): ListAttributesResponse;
  clearAttributesList(): ListAttributesResponse;
  addAttributes(value?: policy_objects_pb.Attribute, index?: number): policy_objects_pb.Attribute;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListAttributesResponse.AsObject;
  static toObject(includeInstance: boolean, msg: ListAttributesResponse): ListAttributesResponse.AsObject;
  static serializeBinaryToWriter(message: ListAttributesResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListAttributesResponse;
  static deserializeBinaryFromReader(message: ListAttributesResponse, reader: jspb.BinaryReader): ListAttributesResponse;
}

export namespace ListAttributesResponse {
  export type AsObject = {
    attributesList: Array<policy_objects_pb.Attribute.AsObject>,
  }
}

export class GetAttributeRequest extends jspb.Message {
  getId(): string;
  setId(value: string): GetAttributeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetAttributeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetAttributeRequest): GetAttributeRequest.AsObject;
  static serializeBinaryToWriter(message: GetAttributeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetAttributeRequest;
  static deserializeBinaryFromReader(message: GetAttributeRequest, reader: jspb.BinaryReader): GetAttributeRequest;
}

export namespace GetAttributeRequest {
  export type AsObject = {
    id: string,
  }
}

export class GetAttributeResponse extends jspb.Message {
  getAttribute(): policy_objects_pb.Attribute | undefined;
  setAttribute(value?: policy_objects_pb.Attribute): GetAttributeResponse;
  hasAttribute(): boolean;
  clearAttribute(): GetAttributeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetAttributeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetAttributeResponse): GetAttributeResponse.AsObject;
  static serializeBinaryToWriter(message: GetAttributeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetAttributeResponse;
  static deserializeBinaryFromReader(message: GetAttributeResponse, reader: jspb.BinaryReader): GetAttributeResponse;
}

export namespace GetAttributeResponse {
  export type AsObject = {
    attribute?: policy_objects_pb.Attribute.AsObject,
  }
}

export class CreateAttributeRequest extends jspb.Message {
  getNamespaceId(): string;
  setNamespaceId(value: string): CreateAttributeRequest;

  getName(): string;
  setName(value: string): CreateAttributeRequest;

  getRule(): policy_objects_pb.AttributeRuleTypeEnum;
  setRule(value: policy_objects_pb.AttributeRuleTypeEnum): CreateAttributeRequest;

  getValuesList(): Array<string>;
  setValuesList(value: Array<string>): CreateAttributeRequest;
  clearValuesList(): CreateAttributeRequest;
  addValues(value: string, index?: number): CreateAttributeRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): CreateAttributeRequest;
  hasMetadata(): boolean;
  clearMetadata(): CreateAttributeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateAttributeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateAttributeRequest): CreateAttributeRequest.AsObject;
  static serializeBinaryToWriter(message: CreateAttributeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateAttributeRequest;
  static deserializeBinaryFromReader(message: CreateAttributeRequest, reader: jspb.BinaryReader): CreateAttributeRequest;
}

export namespace CreateAttributeRequest {
  export type AsObject = {
    namespaceId: string,
    name: string,
    rule: policy_objects_pb.AttributeRuleTypeEnum,
    valuesList: Array<string>,
    metadata?: common_common_pb.MetadataMutable.AsObject,
  }
}

export class CreateAttributeResponse extends jspb.Message {
  getAttribute(): policy_objects_pb.Attribute | undefined;
  setAttribute(value?: policy_objects_pb.Attribute): CreateAttributeResponse;
  hasAttribute(): boolean;
  clearAttribute(): CreateAttributeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateAttributeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateAttributeResponse): CreateAttributeResponse.AsObject;
  static serializeBinaryToWriter(message: CreateAttributeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateAttributeResponse;
  static deserializeBinaryFromReader(message: CreateAttributeResponse, reader: jspb.BinaryReader): CreateAttributeResponse;
}

export namespace CreateAttributeResponse {
  export type AsObject = {
    attribute?: policy_objects_pb.Attribute.AsObject,
  }
}

export class UpdateAttributeRequest extends jspb.Message {
  getId(): string;
  setId(value: string): UpdateAttributeRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): UpdateAttributeRequest;
  hasMetadata(): boolean;
  clearMetadata(): UpdateAttributeRequest;

  getMetadataUpdateBehavior(): common_common_pb.MetadataUpdateEnum;
  setMetadataUpdateBehavior(value: common_common_pb.MetadataUpdateEnum): UpdateAttributeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateAttributeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateAttributeRequest): UpdateAttributeRequest.AsObject;
  static serializeBinaryToWriter(message: UpdateAttributeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateAttributeRequest;
  static deserializeBinaryFromReader(message: UpdateAttributeRequest, reader: jspb.BinaryReader): UpdateAttributeRequest;
}

export namespace UpdateAttributeRequest {
  export type AsObject = {
    id: string,
    metadata?: common_common_pb.MetadataMutable.AsObject,
    metadataUpdateBehavior: common_common_pb.MetadataUpdateEnum,
  }
}

export class UpdateAttributeResponse extends jspb.Message {
  getAttribute(): policy_objects_pb.Attribute | undefined;
  setAttribute(value?: policy_objects_pb.Attribute): UpdateAttributeResponse;
  hasAttribute(): boolean;
  clearAttribute(): UpdateAttributeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateAttributeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateAttributeResponse): UpdateAttributeResponse.AsObject;
  static serializeBinaryToWriter(message: UpdateAttributeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateAttributeResponse;
  static deserializeBinaryFromReader(message: UpdateAttributeResponse, reader: jspb.BinaryReader): UpdateAttributeResponse;
}

export namespace UpdateAttributeResponse {
  export type AsObject = {
    attribute?: policy_objects_pb.Attribute.AsObject,
  }
}

export class DeactivateAttributeRequest extends jspb.Message {
  getId(): string;
  setId(value: string): DeactivateAttributeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeactivateAttributeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DeactivateAttributeRequest): DeactivateAttributeRequest.AsObject;
  static serializeBinaryToWriter(message: DeactivateAttributeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeactivateAttributeRequest;
  static deserializeBinaryFromReader(message: DeactivateAttributeRequest, reader: jspb.BinaryReader): DeactivateAttributeRequest;
}

export namespace DeactivateAttributeRequest {
  export type AsObject = {
    id: string,
  }
}

export class DeactivateAttributeResponse extends jspb.Message {
  getAttribute(): policy_objects_pb.Attribute | undefined;
  setAttribute(value?: policy_objects_pb.Attribute): DeactivateAttributeResponse;
  hasAttribute(): boolean;
  clearAttribute(): DeactivateAttributeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeactivateAttributeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DeactivateAttributeResponse): DeactivateAttributeResponse.AsObject;
  static serializeBinaryToWriter(message: DeactivateAttributeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeactivateAttributeResponse;
  static deserializeBinaryFromReader(message: DeactivateAttributeResponse, reader: jspb.BinaryReader): DeactivateAttributeResponse;
}

export namespace DeactivateAttributeResponse {
  export type AsObject = {
    attribute?: policy_objects_pb.Attribute.AsObject,
  }
}

export class GetAttributeValueRequest extends jspb.Message {
  getId(): string;
  setId(value: string): GetAttributeValueRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetAttributeValueRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetAttributeValueRequest): GetAttributeValueRequest.AsObject;
  static serializeBinaryToWriter(message: GetAttributeValueRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetAttributeValueRequest;
  static deserializeBinaryFromReader(message: GetAttributeValueRequest, reader: jspb.BinaryReader): GetAttributeValueRequest;
}

export namespace GetAttributeValueRequest {
  export type AsObject = {
    id: string,
  }
}

export class GetAttributeValueResponse extends jspb.Message {
  getValue(): policy_objects_pb.Value | undefined;
  setValue(value?: policy_objects_pb.Value): GetAttributeValueResponse;
  hasValue(): boolean;
  clearValue(): GetAttributeValueResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetAttributeValueResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetAttributeValueResponse): GetAttributeValueResponse.AsObject;
  static serializeBinaryToWriter(message: GetAttributeValueResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetAttributeValueResponse;
  static deserializeBinaryFromReader(message: GetAttributeValueResponse, reader: jspb.BinaryReader): GetAttributeValueResponse;
}

export namespace GetAttributeValueResponse {
  export type AsObject = {
    value?: policy_objects_pb.Value.AsObject,
  }
}

export class ListAttributeValuesRequest extends jspb.Message {
  getAttributeId(): string;
  setAttributeId(value: string): ListAttributeValuesRequest;

  getState(): common_common_pb.ActiveStateEnum;
  setState(value: common_common_pb.ActiveStateEnum): ListAttributeValuesRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListAttributeValuesRequest.AsObject;
  static toObject(includeInstance: boolean, msg: ListAttributeValuesRequest): ListAttributeValuesRequest.AsObject;
  static serializeBinaryToWriter(message: ListAttributeValuesRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListAttributeValuesRequest;
  static deserializeBinaryFromReader(message: ListAttributeValuesRequest, reader: jspb.BinaryReader): ListAttributeValuesRequest;
}

export namespace ListAttributeValuesRequest {
  export type AsObject = {
    attributeId: string,
    state: common_common_pb.ActiveStateEnum,
  }
}

export class ListAttributeValuesResponse extends jspb.Message {
  getValuesList(): Array<policy_objects_pb.Value>;
  setValuesList(value: Array<policy_objects_pb.Value>): ListAttributeValuesResponse;
  clearValuesList(): ListAttributeValuesResponse;
  addValues(value?: policy_objects_pb.Value, index?: number): policy_objects_pb.Value;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ListAttributeValuesResponse.AsObject;
  static toObject(includeInstance: boolean, msg: ListAttributeValuesResponse): ListAttributeValuesResponse.AsObject;
  static serializeBinaryToWriter(message: ListAttributeValuesResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ListAttributeValuesResponse;
  static deserializeBinaryFromReader(message: ListAttributeValuesResponse, reader: jspb.BinaryReader): ListAttributeValuesResponse;
}

export namespace ListAttributeValuesResponse {
  export type AsObject = {
    valuesList: Array<policy_objects_pb.Value.AsObject>,
  }
}

export class CreateAttributeValueRequest extends jspb.Message {
  getAttributeId(): string;
  setAttributeId(value: string): CreateAttributeValueRequest;

  getValue(): string;
  setValue(value: string): CreateAttributeValueRequest;

  getMembersList(): Array<string>;
  setMembersList(value: Array<string>): CreateAttributeValueRequest;
  clearMembersList(): CreateAttributeValueRequest;
  addMembers(value: string, index?: number): CreateAttributeValueRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): CreateAttributeValueRequest;
  hasMetadata(): boolean;
  clearMetadata(): CreateAttributeValueRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateAttributeValueRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateAttributeValueRequest): CreateAttributeValueRequest.AsObject;
  static serializeBinaryToWriter(message: CreateAttributeValueRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateAttributeValueRequest;
  static deserializeBinaryFromReader(message: CreateAttributeValueRequest, reader: jspb.BinaryReader): CreateAttributeValueRequest;
}

export namespace CreateAttributeValueRequest {
  export type AsObject = {
    attributeId: string,
    value: string,
    membersList: Array<string>,
    metadata?: common_common_pb.MetadataMutable.AsObject,
  }
}

export class CreateAttributeValueResponse extends jspb.Message {
  getValue(): policy_objects_pb.Value | undefined;
  setValue(value?: policy_objects_pb.Value): CreateAttributeValueResponse;
  hasValue(): boolean;
  clearValue(): CreateAttributeValueResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateAttributeValueResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateAttributeValueResponse): CreateAttributeValueResponse.AsObject;
  static serializeBinaryToWriter(message: CreateAttributeValueResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateAttributeValueResponse;
  static deserializeBinaryFromReader(message: CreateAttributeValueResponse, reader: jspb.BinaryReader): CreateAttributeValueResponse;
}

export namespace CreateAttributeValueResponse {
  export type AsObject = {
    value?: policy_objects_pb.Value.AsObject,
  }
}

export class UpdateAttributeValueRequest extends jspb.Message {
  getId(): string;
  setId(value: string): UpdateAttributeValueRequest;

  getMembersList(): Array<string>;
  setMembersList(value: Array<string>): UpdateAttributeValueRequest;
  clearMembersList(): UpdateAttributeValueRequest;
  addMembers(value: string, index?: number): UpdateAttributeValueRequest;

  getMetadata(): common_common_pb.MetadataMutable | undefined;
  setMetadata(value?: common_common_pb.MetadataMutable): UpdateAttributeValueRequest;
  hasMetadata(): boolean;
  clearMetadata(): UpdateAttributeValueRequest;

  getMetadataUpdateBehavior(): common_common_pb.MetadataUpdateEnum;
  setMetadataUpdateBehavior(value: common_common_pb.MetadataUpdateEnum): UpdateAttributeValueRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateAttributeValueRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateAttributeValueRequest): UpdateAttributeValueRequest.AsObject;
  static serializeBinaryToWriter(message: UpdateAttributeValueRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateAttributeValueRequest;
  static deserializeBinaryFromReader(message: UpdateAttributeValueRequest, reader: jspb.BinaryReader): UpdateAttributeValueRequest;
}

export namespace UpdateAttributeValueRequest {
  export type AsObject = {
    id: string,
    membersList: Array<string>,
    metadata?: common_common_pb.MetadataMutable.AsObject,
    metadataUpdateBehavior: common_common_pb.MetadataUpdateEnum,
  }
}

export class UpdateAttributeValueResponse extends jspb.Message {
  getValue(): policy_objects_pb.Value | undefined;
  setValue(value?: policy_objects_pb.Value): UpdateAttributeValueResponse;
  hasValue(): boolean;
  clearValue(): UpdateAttributeValueResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateAttributeValueResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateAttributeValueResponse): UpdateAttributeValueResponse.AsObject;
  static serializeBinaryToWriter(message: UpdateAttributeValueResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateAttributeValueResponse;
  static deserializeBinaryFromReader(message: UpdateAttributeValueResponse, reader: jspb.BinaryReader): UpdateAttributeValueResponse;
}

export namespace UpdateAttributeValueResponse {
  export type AsObject = {
    value?: policy_objects_pb.Value.AsObject,
  }
}

export class DeactivateAttributeValueRequest extends jspb.Message {
  getId(): string;
  setId(value: string): DeactivateAttributeValueRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeactivateAttributeValueRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DeactivateAttributeValueRequest): DeactivateAttributeValueRequest.AsObject;
  static serializeBinaryToWriter(message: DeactivateAttributeValueRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeactivateAttributeValueRequest;
  static deserializeBinaryFromReader(message: DeactivateAttributeValueRequest, reader: jspb.BinaryReader): DeactivateAttributeValueRequest;
}

export namespace DeactivateAttributeValueRequest {
  export type AsObject = {
    id: string,
  }
}

export class DeactivateAttributeValueResponse extends jspb.Message {
  getValue(): policy_objects_pb.Value | undefined;
  setValue(value?: policy_objects_pb.Value): DeactivateAttributeValueResponse;
  hasValue(): boolean;
  clearValue(): DeactivateAttributeValueResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeactivateAttributeValueResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DeactivateAttributeValueResponse): DeactivateAttributeValueResponse.AsObject;
  static serializeBinaryToWriter(message: DeactivateAttributeValueResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeactivateAttributeValueResponse;
  static deserializeBinaryFromReader(message: DeactivateAttributeValueResponse, reader: jspb.BinaryReader): DeactivateAttributeValueResponse;
}

export namespace DeactivateAttributeValueResponse {
  export type AsObject = {
    value?: policy_objects_pb.Value.AsObject,
  }
}

export class GetAttributeValuesByFqnsRequest extends jspb.Message {
  getFqnsList(): Array<string>;
  setFqnsList(value: Array<string>): GetAttributeValuesByFqnsRequest;
  clearFqnsList(): GetAttributeValuesByFqnsRequest;
  addFqns(value: string, index?: number): GetAttributeValuesByFqnsRequest;

  getWithValue(): policy_selectors_pb.AttributeValueSelector | undefined;
  setWithValue(value?: policy_selectors_pb.AttributeValueSelector): GetAttributeValuesByFqnsRequest;
  hasWithValue(): boolean;
  clearWithValue(): GetAttributeValuesByFqnsRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetAttributeValuesByFqnsRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetAttributeValuesByFqnsRequest): GetAttributeValuesByFqnsRequest.AsObject;
  static serializeBinaryToWriter(message: GetAttributeValuesByFqnsRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetAttributeValuesByFqnsRequest;
  static deserializeBinaryFromReader(message: GetAttributeValuesByFqnsRequest, reader: jspb.BinaryReader): GetAttributeValuesByFqnsRequest;
}

export namespace GetAttributeValuesByFqnsRequest {
  export type AsObject = {
    fqnsList: Array<string>,
    withValue?: policy_selectors_pb.AttributeValueSelector.AsObject,
  }
}

export class GetAttributeValuesByFqnsResponse extends jspb.Message {
  getFqnAttributeValuesMap(): jspb.Map<string, GetAttributeValuesByFqnsResponse.AttributeAndValue>;
  clearFqnAttributeValuesMap(): GetAttributeValuesByFqnsResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetAttributeValuesByFqnsResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetAttributeValuesByFqnsResponse): GetAttributeValuesByFqnsResponse.AsObject;
  static serializeBinaryToWriter(message: GetAttributeValuesByFqnsResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetAttributeValuesByFqnsResponse;
  static deserializeBinaryFromReader(message: GetAttributeValuesByFqnsResponse, reader: jspb.BinaryReader): GetAttributeValuesByFqnsResponse;
}

export namespace GetAttributeValuesByFqnsResponse {
  export type AsObject = {
    fqnAttributeValuesMap: Array<[string, GetAttributeValuesByFqnsResponse.AttributeAndValue.AsObject]>,
  }

  export class AttributeAndValue extends jspb.Message {
    getAttribute(): policy_objects_pb.Attribute | undefined;
    setAttribute(value?: policy_objects_pb.Attribute): AttributeAndValue;
    hasAttribute(): boolean;
    clearAttribute(): AttributeAndValue;

    getValue(): policy_objects_pb.Value | undefined;
    setValue(value?: policy_objects_pb.Value): AttributeAndValue;
    hasValue(): boolean;
    clearValue(): AttributeAndValue;

    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): AttributeAndValue.AsObject;
    static toObject(includeInstance: boolean, msg: AttributeAndValue): AttributeAndValue.AsObject;
    static serializeBinaryToWriter(message: AttributeAndValue, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): AttributeAndValue;
    static deserializeBinaryFromReader(message: AttributeAndValue, reader: jspb.BinaryReader): AttributeAndValue;
  }

  export namespace AttributeAndValue {
    export type AsObject = {
      attribute?: policy_objects_pb.Attribute.AsObject,
      value?: policy_objects_pb.Value.AsObject,
    }
  }

}

export class AssignKeyAccessServerToAttributeRequest extends jspb.Message {
  getAttributeKeyAccessServer(): AttributeKeyAccessServer | undefined;
  setAttributeKeyAccessServer(value?: AttributeKeyAccessServer): AssignKeyAccessServerToAttributeRequest;
  hasAttributeKeyAccessServer(): boolean;
  clearAttributeKeyAccessServer(): AssignKeyAccessServerToAttributeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AssignKeyAccessServerToAttributeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: AssignKeyAccessServerToAttributeRequest): AssignKeyAccessServerToAttributeRequest.AsObject;
  static serializeBinaryToWriter(message: AssignKeyAccessServerToAttributeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AssignKeyAccessServerToAttributeRequest;
  static deserializeBinaryFromReader(message: AssignKeyAccessServerToAttributeRequest, reader: jspb.BinaryReader): AssignKeyAccessServerToAttributeRequest;
}

export namespace AssignKeyAccessServerToAttributeRequest {
  export type AsObject = {
    attributeKeyAccessServer?: AttributeKeyAccessServer.AsObject,
  }
}

export class AssignKeyAccessServerToAttributeResponse extends jspb.Message {
  getAttributeKeyAccessServer(): AttributeKeyAccessServer | undefined;
  setAttributeKeyAccessServer(value?: AttributeKeyAccessServer): AssignKeyAccessServerToAttributeResponse;
  hasAttributeKeyAccessServer(): boolean;
  clearAttributeKeyAccessServer(): AssignKeyAccessServerToAttributeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AssignKeyAccessServerToAttributeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: AssignKeyAccessServerToAttributeResponse): AssignKeyAccessServerToAttributeResponse.AsObject;
  static serializeBinaryToWriter(message: AssignKeyAccessServerToAttributeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AssignKeyAccessServerToAttributeResponse;
  static deserializeBinaryFromReader(message: AssignKeyAccessServerToAttributeResponse, reader: jspb.BinaryReader): AssignKeyAccessServerToAttributeResponse;
}

export namespace AssignKeyAccessServerToAttributeResponse {
  export type AsObject = {
    attributeKeyAccessServer?: AttributeKeyAccessServer.AsObject,
  }
}

export class RemoveKeyAccessServerFromAttributeRequest extends jspb.Message {
  getAttributeKeyAccessServer(): AttributeKeyAccessServer | undefined;
  setAttributeKeyAccessServer(value?: AttributeKeyAccessServer): RemoveKeyAccessServerFromAttributeRequest;
  hasAttributeKeyAccessServer(): boolean;
  clearAttributeKeyAccessServer(): RemoveKeyAccessServerFromAttributeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RemoveKeyAccessServerFromAttributeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: RemoveKeyAccessServerFromAttributeRequest): RemoveKeyAccessServerFromAttributeRequest.AsObject;
  static serializeBinaryToWriter(message: RemoveKeyAccessServerFromAttributeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RemoveKeyAccessServerFromAttributeRequest;
  static deserializeBinaryFromReader(message: RemoveKeyAccessServerFromAttributeRequest, reader: jspb.BinaryReader): RemoveKeyAccessServerFromAttributeRequest;
}

export namespace RemoveKeyAccessServerFromAttributeRequest {
  export type AsObject = {
    attributeKeyAccessServer?: AttributeKeyAccessServer.AsObject,
  }
}

export class RemoveKeyAccessServerFromAttributeResponse extends jspb.Message {
  getAttributeKeyAccessServer(): AttributeKeyAccessServer | undefined;
  setAttributeKeyAccessServer(value?: AttributeKeyAccessServer): RemoveKeyAccessServerFromAttributeResponse;
  hasAttributeKeyAccessServer(): boolean;
  clearAttributeKeyAccessServer(): RemoveKeyAccessServerFromAttributeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RemoveKeyAccessServerFromAttributeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: RemoveKeyAccessServerFromAttributeResponse): RemoveKeyAccessServerFromAttributeResponse.AsObject;
  static serializeBinaryToWriter(message: RemoveKeyAccessServerFromAttributeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RemoveKeyAccessServerFromAttributeResponse;
  static deserializeBinaryFromReader(message: RemoveKeyAccessServerFromAttributeResponse, reader: jspb.BinaryReader): RemoveKeyAccessServerFromAttributeResponse;
}

export namespace RemoveKeyAccessServerFromAttributeResponse {
  export type AsObject = {
    attributeKeyAccessServer?: AttributeKeyAccessServer.AsObject,
  }
}

export class AssignKeyAccessServerToValueRequest extends jspb.Message {
  getValueKeyAccessServer(): ValueKeyAccessServer | undefined;
  setValueKeyAccessServer(value?: ValueKeyAccessServer): AssignKeyAccessServerToValueRequest;
  hasValueKeyAccessServer(): boolean;
  clearValueKeyAccessServer(): AssignKeyAccessServerToValueRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AssignKeyAccessServerToValueRequest.AsObject;
  static toObject(includeInstance: boolean, msg: AssignKeyAccessServerToValueRequest): AssignKeyAccessServerToValueRequest.AsObject;
  static serializeBinaryToWriter(message: AssignKeyAccessServerToValueRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AssignKeyAccessServerToValueRequest;
  static deserializeBinaryFromReader(message: AssignKeyAccessServerToValueRequest, reader: jspb.BinaryReader): AssignKeyAccessServerToValueRequest;
}

export namespace AssignKeyAccessServerToValueRequest {
  export type AsObject = {
    valueKeyAccessServer?: ValueKeyAccessServer.AsObject,
  }
}

export class AssignKeyAccessServerToValueResponse extends jspb.Message {
  getValueKeyAccessServer(): ValueKeyAccessServer | undefined;
  setValueKeyAccessServer(value?: ValueKeyAccessServer): AssignKeyAccessServerToValueResponse;
  hasValueKeyAccessServer(): boolean;
  clearValueKeyAccessServer(): AssignKeyAccessServerToValueResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AssignKeyAccessServerToValueResponse.AsObject;
  static toObject(includeInstance: boolean, msg: AssignKeyAccessServerToValueResponse): AssignKeyAccessServerToValueResponse.AsObject;
  static serializeBinaryToWriter(message: AssignKeyAccessServerToValueResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AssignKeyAccessServerToValueResponse;
  static deserializeBinaryFromReader(message: AssignKeyAccessServerToValueResponse, reader: jspb.BinaryReader): AssignKeyAccessServerToValueResponse;
}

export namespace AssignKeyAccessServerToValueResponse {
  export type AsObject = {
    valueKeyAccessServer?: ValueKeyAccessServer.AsObject,
  }
}

export class RemoveKeyAccessServerFromValueRequest extends jspb.Message {
  getValueKeyAccessServer(): ValueKeyAccessServer | undefined;
  setValueKeyAccessServer(value?: ValueKeyAccessServer): RemoveKeyAccessServerFromValueRequest;
  hasValueKeyAccessServer(): boolean;
  clearValueKeyAccessServer(): RemoveKeyAccessServerFromValueRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RemoveKeyAccessServerFromValueRequest.AsObject;
  static toObject(includeInstance: boolean, msg: RemoveKeyAccessServerFromValueRequest): RemoveKeyAccessServerFromValueRequest.AsObject;
  static serializeBinaryToWriter(message: RemoveKeyAccessServerFromValueRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RemoveKeyAccessServerFromValueRequest;
  static deserializeBinaryFromReader(message: RemoveKeyAccessServerFromValueRequest, reader: jspb.BinaryReader): RemoveKeyAccessServerFromValueRequest;
}

export namespace RemoveKeyAccessServerFromValueRequest {
  export type AsObject = {
    valueKeyAccessServer?: ValueKeyAccessServer.AsObject,
  }
}

export class RemoveKeyAccessServerFromValueResponse extends jspb.Message {
  getValueKeyAccessServer(): ValueKeyAccessServer | undefined;
  setValueKeyAccessServer(value?: ValueKeyAccessServer): RemoveKeyAccessServerFromValueResponse;
  hasValueKeyAccessServer(): boolean;
  clearValueKeyAccessServer(): RemoveKeyAccessServerFromValueResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RemoveKeyAccessServerFromValueResponse.AsObject;
  static toObject(includeInstance: boolean, msg: RemoveKeyAccessServerFromValueResponse): RemoveKeyAccessServerFromValueResponse.AsObject;
  static serializeBinaryToWriter(message: RemoveKeyAccessServerFromValueResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RemoveKeyAccessServerFromValueResponse;
  static deserializeBinaryFromReader(message: RemoveKeyAccessServerFromValueResponse, reader: jspb.BinaryReader): RemoveKeyAccessServerFromValueResponse;
}

export namespace RemoveKeyAccessServerFromValueResponse {
  export type AsObject = {
    valueKeyAccessServer?: ValueKeyAccessServer.AsObject,
  }
}

