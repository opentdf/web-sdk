import * as jspb from 'google-protobuf'

import * as google_protobuf_timestamp_pb from 'google-protobuf/google/protobuf/timestamp_pb'; // proto import: "google/protobuf/timestamp.proto"


export class Metadata extends jspb.Message {
  getCreatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setCreatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Metadata;
  hasCreatedAt(): boolean;
  clearCreatedAt(): Metadata;

  getUpdatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setUpdatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Metadata;
  hasUpdatedAt(): boolean;
  clearUpdatedAt(): Metadata;

  getLabelsMap(): jspb.Map<string, string>;
  clearLabelsMap(): Metadata;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Metadata.AsObject;
  static toObject(includeInstance: boolean, msg: Metadata): Metadata.AsObject;
  static serializeBinaryToWriter(message: Metadata, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Metadata;
  static deserializeBinaryFromReader(message: Metadata, reader: jspb.BinaryReader): Metadata;
}

export namespace Metadata {
  export type AsObject = {
    createdAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    updatedAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    labelsMap: Array<[string, string]>,
  }
}

export class MetadataMutable extends jspb.Message {
  getLabelsMap(): jspb.Map<string, string>;
  clearLabelsMap(): MetadataMutable;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): MetadataMutable.AsObject;
  static toObject(includeInstance: boolean, msg: MetadataMutable): MetadataMutable.AsObject;
  static serializeBinaryToWriter(message: MetadataMutable, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): MetadataMutable;
  static deserializeBinaryFromReader(message: MetadataMutable, reader: jspb.BinaryReader): MetadataMutable;
}

export namespace MetadataMutable {
  export type AsObject = {
    labelsMap: Array<[string, string]>,
  }
}

export enum MetadataUpdateEnum { 
  METADATA_UPDATE_ENUM_UNSPECIFIED = 0,
  METADATA_UPDATE_ENUM_EXTEND = 1,
  METADATA_UPDATE_ENUM_REPLACE = 2,
}
export enum ActiveStateEnum { 
  ACTIVE_STATE_ENUM_UNSPECIFIED = 0,
  ACTIVE_STATE_ENUM_ACTIVE = 1,
  ACTIVE_STATE_ENUM_INACTIVE = 2,
  ACTIVE_STATE_ENUM_ANY = 3,
}
