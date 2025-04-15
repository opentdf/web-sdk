// @generated by protoc-gen-es v2.2.5 with parameter "target=ts,import_extension=.js"
// @generated from file common/common.proto (package common, syntax proto3)
/* eslint-disable */

import type { GenEnum, GenFile, GenMessage } from "@bufbuild/protobuf/codegenv1";
import { enumDesc, fileDesc, messageDesc } from "@bufbuild/protobuf/codegenv1";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { file_google_protobuf_timestamp } from "@bufbuild/protobuf/wkt";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file common/common.proto.
 */
export const file_common_common: GenFile = /*@__PURE__*/
  fileDesc("ChNjb21tb24vY29tbW9uLnByb3RvEgZjb21tb24ixwEKCE1ldGFkYXRhEi4KCmNyZWF0ZWRfYXQYASABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wEi4KCnVwZGF0ZWRfYXQYAiABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wEiwKBmxhYmVscxgDIAMoCzIcLmNvbW1vbi5NZXRhZGF0YS5MYWJlbHNFbnRyeRotCgtMYWJlbHNFbnRyeRILCgNrZXkYASABKAkSDQoFdmFsdWUYAiABKAk6AjgBInUKD01ldGFkYXRhTXV0YWJsZRIzCgZsYWJlbHMYAyADKAsyIy5jb21tb24uTWV0YWRhdGFNdXRhYmxlLkxhYmVsc0VudHJ5Gi0KC0xhYmVsc0VudHJ5EgsKA2tleRgBIAEoCRINCgV2YWx1ZRgCIAEoCToCOAEqfQoSTWV0YWRhdGFVcGRhdGVFbnVtEiQKIE1FVEFEQVRBX1VQREFURV9FTlVNX1VOU1BFQ0lGSUVEEAASHwobTUVUQURBVEFfVVBEQVRFX0VOVU1fRVhURU5EEAESIAocTUVUQURBVEFfVVBEQVRFX0VOVU1fUkVQTEFDRRACKo0BCg9BY3RpdmVTdGF0ZUVudW0SIQodQUNUSVZFX1NUQVRFX0VOVU1fVU5TUEVDSUZJRUQQABIcChhBQ1RJVkVfU1RBVEVfRU5VTV9BQ1RJVkUQARIeChpBQ1RJVkVfU1RBVEVfRU5VTV9JTkFDVElWRRACEhkKFUFDVElWRV9TVEFURV9FTlVNX0FOWRADYgZwcm90bzM", [file_google_protobuf_timestamp]);

/**
 * Struct to uniquely identify a resource with optional additional metadata
 *
 * @generated from message common.Metadata
 */
export type Metadata = Message<"common.Metadata"> & {
  /**
   * created_at set by server (entity who created will recorded in an audit event)
   *
   * @generated from field: google.protobuf.Timestamp created_at = 1;
   */
  createdAt?: Timestamp;

  /**
   * updated_at set by server (entity who updated will recorded in an audit event)
   *
   * @generated from field: google.protobuf.Timestamp updated_at = 2;
   */
  updatedAt?: Timestamp;

  /**
   * optional short description
   *
   * @generated from field: map<string, string> labels = 3;
   */
  labels: { [key: string]: string };
};

/**
 * Describes the message common.Metadata.
 * Use `create(MetadataSchema)` to create a new message.
 */
export const MetadataSchema: GenMessage<Metadata> = /*@__PURE__*/
  messageDesc(file_common_common, 0);

/**
 * @generated from message common.MetadataMutable
 */
export type MetadataMutable = Message<"common.MetadataMutable"> & {
  /**
   * optional labels
   *
   * @generated from field: map<string, string> labels = 3;
   */
  labels: { [key: string]: string };
};

/**
 * Describes the message common.MetadataMutable.
 * Use `create(MetadataMutableSchema)` to create a new message.
 */
export const MetadataMutableSchema: GenMessage<MetadataMutable> = /*@__PURE__*/
  messageDesc(file_common_common, 1);

/**
 * @generated from enum common.MetadataUpdateEnum
 */
export enum MetadataUpdateEnum {
  /**
   * unspecified update type
   *
   * @generated from enum value: METADATA_UPDATE_ENUM_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * only update the fields that are provided
   *
   * @generated from enum value: METADATA_UPDATE_ENUM_EXTEND = 1;
   */
  EXTEND = 1,

  /**
   * replace the entire metadata with the provided metadata
   *
   * @generated from enum value: METADATA_UPDATE_ENUM_REPLACE = 2;
   */
  REPLACE = 2,
}

/**
 * Describes the enum common.MetadataUpdateEnum.
 */
export const MetadataUpdateEnumSchema: GenEnum<MetadataUpdateEnum> = /*@__PURE__*/
  enumDesc(file_common_common, 0);

/**
 * buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package
 *
 * @generated from enum common.ActiveStateEnum
 */
export enum ActiveStateEnum {
  /**
   * @generated from enum value: ACTIVE_STATE_ENUM_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * @generated from enum value: ACTIVE_STATE_ENUM_ACTIVE = 1;
   */
  ACTIVE = 1,

  /**
   * @generated from enum value: ACTIVE_STATE_ENUM_INACTIVE = 2;
   */
  INACTIVE = 2,

  /**
   * @generated from enum value: ACTIVE_STATE_ENUM_ANY = 3;
   */
  ANY = 3,
}

/**
 * Describes the enum common.ActiveStateEnum.
 */
export const ActiveStateEnumSchema: GenEnum<ActiveStateEnum> = /*@__PURE__*/
  enumDesc(file_common_common, 1);

