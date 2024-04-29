/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as CommonCommon from "../../common/common.pb"
import * as fm from "../../fetch.pb"
import * as PolicyObjects from "../objects.pb"
export type GetNamespaceRequest = {
  id?: string
}

export type GetNamespaceResponse = {
  namespace?: PolicyObjects.Namespace
}

export type ListNamespacesRequest = {
  state?: CommonCommon.ActiveStateEnum
}

export type ListNamespacesResponse = {
  namespaces?: PolicyObjects.Namespace[]
}

export type CreateNamespaceRequest = {
  name?: string
  metadata?: CommonCommon.MetadataMutable
}

export type CreateNamespaceResponse = {
  namespace?: PolicyObjects.Namespace
}

export type UpdateNamespaceRequest = {
  id?: string
  metadata?: CommonCommon.MetadataMutable
  metadataUpdateBehavior?: CommonCommon.MetadataUpdateEnum
}

export type UpdateNamespaceResponse = {
  namespace?: PolicyObjects.Namespace
}

export type DeactivateNamespaceRequest = {
  id?: string
}

export type DeactivateNamespaceResponse = {
}

export class NamespaceService {
  static GetNamespace(req: GetNamespaceRequest, initReq?: fm.InitReq): Promise<GetNamespaceResponse> {
    return fm.fetchReq<GetNamespaceRequest, GetNamespaceResponse>(`/attributes/namespaces/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static ListNamespaces(req: ListNamespacesRequest, initReq?: fm.InitReq): Promise<ListNamespacesResponse> {
    return fm.fetchReq<ListNamespacesRequest, ListNamespacesResponse>(`/attributes/namespaces?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static CreateNamespace(req: CreateNamespaceRequest, initReq?: fm.InitReq): Promise<CreateNamespaceResponse> {
    return fm.fetchReq<CreateNamespaceRequest, CreateNamespaceResponse>(`/attributes/namespaces`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateNamespace(req: UpdateNamespaceRequest, initReq?: fm.InitReq): Promise<UpdateNamespaceResponse> {
    return fm.fetchReq<UpdateNamespaceRequest, UpdateNamespaceResponse>(`/attributes/namespaces/${req["id"]}`, {...initReq, method: "PATCH", body: JSON.stringify(req, fm.replacer)})
  }
  static DeactivateNamespace(req: DeactivateNamespaceRequest, initReq?: fm.InitReq): Promise<DeactivateNamespaceResponse> {
    return fm.fetchReq<DeactivateNamespaceRequest, DeactivateNamespaceResponse>(`/attributes/namespaces/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}