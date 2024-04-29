/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as fm from "../fetch.pb"
import * as GoogleProtobufStruct from "../google/protobuf/struct.pb"
export type WellKnownConfig = {
  configuration?: {[key: string]: GoogleProtobufStruct.Struct}
}

export type GetWellKnownConfigurationRequest = {
}

export type GetWellKnownConfigurationResponse = {
  configuration?: GoogleProtobufStruct.Struct
}

export class WellKnownService {
  static GetWellKnownConfiguration(req: GetWellKnownConfigurationRequest, initReq?: fm.InitReq): Promise<GetWellKnownConfigurationResponse> {
    return fm.fetchReq<GetWellKnownConfigurationRequest, GetWellKnownConfigurationResponse>(`/.well-known/opentdf-configuration?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
}