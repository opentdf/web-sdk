import * as jspb from 'google-protobuf';

import * as google_api_annotations_pb from '../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as google_protobuf_struct_pb from 'google-protobuf/google/protobuf/struct_pb'; // proto import: "google/protobuf/struct.proto"

export class WellKnownConfig extends jspb.Message {
  getConfigurationMap(): jspb.Map<string, google_protobuf_struct_pb.Struct>;
  clearConfigurationMap(): WellKnownConfig;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): WellKnownConfig.AsObject;
  static toObject(includeInstance: boolean, msg: WellKnownConfig): WellKnownConfig.AsObject;
  static serializeBinaryToWriter(message: WellKnownConfig, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): WellKnownConfig;
  static deserializeBinaryFromReader(
    message: WellKnownConfig,
    reader: jspb.BinaryReader
  ): WellKnownConfig;
}

export namespace WellKnownConfig {
  export type AsObject = {
    configurationMap: Array<[string, google_protobuf_struct_pb.Struct.AsObject]>;
  };
}

export class GetWellKnownConfigurationRequest extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetWellKnownConfigurationRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetWellKnownConfigurationRequest
  ): GetWellKnownConfigurationRequest.AsObject;
  static serializeBinaryToWriter(
    message: GetWellKnownConfigurationRequest,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetWellKnownConfigurationRequest;
  static deserializeBinaryFromReader(
    message: GetWellKnownConfigurationRequest,
    reader: jspb.BinaryReader
  ): GetWellKnownConfigurationRequest;
}

export namespace GetWellKnownConfigurationRequest {
  export type AsObject = {};
}

export class GetWellKnownConfigurationResponse extends jspb.Message {
  getConfiguration(): google_protobuf_struct_pb.Struct | undefined;
  setConfiguration(value?: google_protobuf_struct_pb.Struct): GetWellKnownConfigurationResponse;
  hasConfiguration(): boolean;
  clearConfiguration(): GetWellKnownConfigurationResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetWellKnownConfigurationResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetWellKnownConfigurationResponse
  ): GetWellKnownConfigurationResponse.AsObject;
  static serializeBinaryToWriter(
    message: GetWellKnownConfigurationResponse,
    writer: jspb.BinaryWriter
  ): void;
  static deserializeBinary(bytes: Uint8Array): GetWellKnownConfigurationResponse;
  static deserializeBinaryFromReader(
    message: GetWellKnownConfigurationResponse,
    reader: jspb.BinaryReader
  ): GetWellKnownConfigurationResponse;
}

export namespace GetWellKnownConfigurationResponse {
  export type AsObject = {
    configuration?: google_protobuf_struct_pb.Struct.AsObject;
  };
}
