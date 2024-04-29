/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as GoogleProtobufAny from "../google/protobuf/any.pb"
import * as GoogleProtobufStruct from "../google/protobuf/struct.pb"
import * as AuthorizationAuthorization from "./authorization.pb"
export type IdpConfig = {
  config?: GoogleProtobufStruct.Struct
}

export type IdpPluginRequest = {
  entities?: AuthorizationAuthorization.Entity[]
}

export type IdpEntityRepresentation = {
  additionalProps?: GoogleProtobufStruct.Struct[]
  originalId?: string
}

export type IdpPluginResponse = {
  entityRepresentations?: IdpEntityRepresentation[]
}

export type EntityNotFoundError = {
  code?: number
  message?: string
  details?: GoogleProtobufAny.Any[]
  entity?: string
}