/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as GoogleProtobufTimestamp from "../google/protobuf/timestamp.pb"

export enum MetadataUpdateEnum {
  METADATA_UPDATE_ENUM_UNSPECIFIED = "METADATA_UPDATE_ENUM_UNSPECIFIED",
  METADATA_UPDATE_ENUM_EXTEND = "METADATA_UPDATE_ENUM_EXTEND",
  METADATA_UPDATE_ENUM_REPLACE = "METADATA_UPDATE_ENUM_REPLACE",
}

export enum ActiveStateEnum {
  ACTIVE_STATE_ENUM_UNSPECIFIED = "ACTIVE_STATE_ENUM_UNSPECIFIED",
  ACTIVE_STATE_ENUM_ACTIVE = "ACTIVE_STATE_ENUM_ACTIVE",
  ACTIVE_STATE_ENUM_INACTIVE = "ACTIVE_STATE_ENUM_INACTIVE",
  ACTIVE_STATE_ENUM_ANY = "ACTIVE_STATE_ENUM_ANY",
}

export type Metadata = {
  createdAt?: GoogleProtobufTimestamp.Timestamp
  updatedAt?: GoogleProtobufTimestamp.Timestamp
  labels?: {[key: string]: string}
}

export type MetadataMutable = {
  labels?: {[key: string]: string}
}