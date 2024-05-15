import * as jspb from 'google-protobuf'

import * as authorization_authorization_pb from '../authorization/authorization_pb'; // proto import: "authorization/authorization.proto"
import * as google_protobuf_struct_pb from 'google-protobuf/google/protobuf/struct_pb'; // proto import: "google/protobuf/struct.proto"
import * as google_protobuf_any_pb from 'google-protobuf/google/protobuf/any_pb'; // proto import: "google/protobuf/any.proto"
import * as google_api_annotations_pb from '../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"


export class ResolveEntitiesRequest extends jspb.Message {
  getEntitiesList(): Array<authorization_authorization_pb.Entity>;
  setEntitiesList(value: Array<authorization_authorization_pb.Entity>): ResolveEntitiesRequest;
  clearEntitiesList(): ResolveEntitiesRequest;
  addEntities(value?: authorization_authorization_pb.Entity, index?: number): authorization_authorization_pb.Entity;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ResolveEntitiesRequest.AsObject;
  static toObject(includeInstance: boolean, msg: ResolveEntitiesRequest): ResolveEntitiesRequest.AsObject;
  static serializeBinaryToWriter(message: ResolveEntitiesRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ResolveEntitiesRequest;
  static deserializeBinaryFromReader(message: ResolveEntitiesRequest, reader: jspb.BinaryReader): ResolveEntitiesRequest;
}

export namespace ResolveEntitiesRequest {
  export type AsObject = {
    entitiesList: Array<authorization_authorization_pb.Entity.AsObject>,
  }
}

export class EntityRepresentation extends jspb.Message {
  getAdditionalPropsList(): Array<google_protobuf_struct_pb.Struct>;
  setAdditionalPropsList(value: Array<google_protobuf_struct_pb.Struct>): EntityRepresentation;
  clearAdditionalPropsList(): EntityRepresentation;
  addAdditionalProps(value?: google_protobuf_struct_pb.Struct, index?: number): google_protobuf_struct_pb.Struct;

  getOriginalId(): string;
  setOriginalId(value: string): EntityRepresentation;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): EntityRepresentation.AsObject;
  static toObject(includeInstance: boolean, msg: EntityRepresentation): EntityRepresentation.AsObject;
  static serializeBinaryToWriter(message: EntityRepresentation, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): EntityRepresentation;
  static deserializeBinaryFromReader(message: EntityRepresentation, reader: jspb.BinaryReader): EntityRepresentation;
}

export namespace EntityRepresentation {
  export type AsObject = {
    additionalPropsList: Array<google_protobuf_struct_pb.Struct.AsObject>,
    originalId: string,
  }
}

export class ResolveEntitiesResponse extends jspb.Message {
  getEntityRepresentationsList(): Array<EntityRepresentation>;
  setEntityRepresentationsList(value: Array<EntityRepresentation>): ResolveEntitiesResponse;
  clearEntityRepresentationsList(): ResolveEntitiesResponse;
  addEntityRepresentations(value?: EntityRepresentation, index?: number): EntityRepresentation;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ResolveEntitiesResponse.AsObject;
  static toObject(includeInstance: boolean, msg: ResolveEntitiesResponse): ResolveEntitiesResponse.AsObject;
  static serializeBinaryToWriter(message: ResolveEntitiesResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ResolveEntitiesResponse;
  static deserializeBinaryFromReader(message: ResolveEntitiesResponse, reader: jspb.BinaryReader): ResolveEntitiesResponse;
}

export namespace ResolveEntitiesResponse {
  export type AsObject = {
    entityRepresentationsList: Array<EntityRepresentation.AsObject>,
  }
}

export class EntityNotFoundError extends jspb.Message {
  getCode(): number;
  setCode(value: number): EntityNotFoundError;

  getMessage(): string;
  setMessage(value: string): EntityNotFoundError;

  getDetailsList(): Array<google_protobuf_any_pb.Any>;
  setDetailsList(value: Array<google_protobuf_any_pb.Any>): EntityNotFoundError;
  clearDetailsList(): EntityNotFoundError;
  addDetails(value?: google_protobuf_any_pb.Any, index?: number): google_protobuf_any_pb.Any;

  getEntity(): string;
  setEntity(value: string): EntityNotFoundError;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): EntityNotFoundError.AsObject;
  static toObject(includeInstance: boolean, msg: EntityNotFoundError): EntityNotFoundError.AsObject;
  static serializeBinaryToWriter(message: EntityNotFoundError, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): EntityNotFoundError;
  static deserializeBinaryFromReader(message: EntityNotFoundError, reader: jspb.BinaryReader): EntityNotFoundError;
}

export namespace EntityNotFoundError {
  export type AsObject = {
    code: number,
    message: string,
    detailsList: Array<google_protobuf_any_pb.Any.AsObject>,
    entity: string,
  }
}

