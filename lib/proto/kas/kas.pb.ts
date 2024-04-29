/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as fm from "../fetch.pb"
import * as GoogleProtobufStruct from "../google/protobuf/struct.pb"
import * as GoogleProtobufWrappers from "../google/protobuf/wrappers.pb"
export type InfoRequest = {
}

export type InfoResponse = {
  version?: string
}

export type LegacyPublicKeyRequest = {
  algorithm?: string
}

export type PublicKeyRequest = {
  algorithm?: string
  fmt?: string
  v?: string
}

export type PublicKeyResponse = {
  publicKey?: string
}

export type RewrapRequest = {
  signedRequestToken?: string
}

export type RewrapResponse = {
  metadata?: {[key: string]: GoogleProtobufStruct.Value}
  entityWrappedKey?: Uint8Array
  sessionPublicKey?: string
  schemaVersion?: string
}

export class AccessService {
  static Info(req: InfoRequest, initReq?: fm.InitReq): Promise<InfoResponse> {
    return fm.fetchReq<InfoRequest, InfoResponse>(`/kas?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static PublicKey(req: PublicKeyRequest, initReq?: fm.InitReq): Promise<PublicKeyResponse> {
    return fm.fetchReq<PublicKeyRequest, PublicKeyResponse>(`/kas/v2/kas_public_key?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static LegacyPublicKey(req: LegacyPublicKeyRequest, initReq?: fm.InitReq): Promise<GoogleProtobufWrappers.StringValue> {
    return fm.fetchReq<LegacyPublicKeyRequest, GoogleProtobufWrappers.StringValue>(`/kas/kas_public_key?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static Rewrap(req: RewrapRequest, initReq?: fm.InitReq): Promise<RewrapResponse> {
    return fm.fetchReq<RewrapRequest, RewrapResponse>(`/kas/v2/rewrap`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
}