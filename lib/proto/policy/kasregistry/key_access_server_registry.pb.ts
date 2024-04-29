/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as CommonCommon from "../../common/common.pb"
import * as fm from "../../fetch.pb"
import * as PolicyObjects from "../objects.pb"
export type GetKeyAccessServerRequest = {
  id?: string
}

export type GetKeyAccessServerResponse = {
  keyAccessServer?: PolicyObjects.KeyAccessServer
}

export type ListKeyAccessServersRequest = {
}

export type ListKeyAccessServersResponse = {
  keyAccessServers?: PolicyObjects.KeyAccessServer[]
}

export type CreateKeyAccessServerRequest = {
  uri?: string
  publicKey?: PolicyObjects.PublicKey
  metadata?: CommonCommon.MetadataMutable
}

export type CreateKeyAccessServerResponse = {
  keyAccessServer?: PolicyObjects.KeyAccessServer
}

export type UpdateKeyAccessServerRequest = {
  id?: string
  uri?: string
  publicKey?: PolicyObjects.PublicKey
  metadata?: CommonCommon.MetadataMutable
  metadataUpdateBehavior?: CommonCommon.MetadataUpdateEnum
}

export type UpdateKeyAccessServerResponse = {
  keyAccessServer?: PolicyObjects.KeyAccessServer
}

export type DeleteKeyAccessServerRequest = {
  id?: string
}

export type DeleteKeyAccessServerResponse = {
  keyAccessServer?: PolicyObjects.KeyAccessServer
}

export class KeyAccessServerRegistryService {
  static ListKeyAccessServers(req: ListKeyAccessServersRequest, initReq?: fm.InitReq): Promise<ListKeyAccessServersResponse> {
    return fm.fetchReq<ListKeyAccessServersRequest, ListKeyAccessServersResponse>(`/key-access-servers?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetKeyAccessServer(req: GetKeyAccessServerRequest, initReq?: fm.InitReq): Promise<GetKeyAccessServerResponse> {
    return fm.fetchReq<GetKeyAccessServerRequest, GetKeyAccessServerResponse>(`/key-access-servers/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateKeyAccessServer(req: CreateKeyAccessServerRequest, initReq?: fm.InitReq): Promise<CreateKeyAccessServerResponse> {
    return fm.fetchReq<CreateKeyAccessServerRequest, CreateKeyAccessServerResponse>(`/key-access-servers`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateKeyAccessServer(req: UpdateKeyAccessServerRequest, initReq?: fm.InitReq): Promise<UpdateKeyAccessServerResponse> {
    return fm.fetchReq<UpdateKeyAccessServerRequest, UpdateKeyAccessServerResponse>(`/key-access-servers/${req["id"]}`, {...initReq, method: "PATCH", body: JSON.stringify(req, fm.replacer)})
  }
  static DeleteKeyAccessServer(req: DeleteKeyAccessServerRequest, initReq?: fm.InitReq): Promise<DeleteKeyAccessServerResponse> {
    return fm.fetchReq<DeleteKeyAccessServerRequest, DeleteKeyAccessServerResponse>(`/key-access-servers/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}