/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as CommonCommon from "../../common/common.pb"
import * as fm from "../../fetch.pb"
import * as PolicyObjects from "../objects.pb"
export type ListResourceMappingsRequest = {
}

export type ListResourceMappingsResponse = {
  resourceMappings?: PolicyObjects.ResourceMapping[]
}

export type GetResourceMappingRequest = {
  id?: string
}

export type GetResourceMappingResponse = {
  resourceMapping?: PolicyObjects.ResourceMapping
}

export type CreateResourceMappingRequest = {
  attributeValueId?: string
  terms?: string[]
  metadata?: CommonCommon.MetadataMutable
}

export type CreateResourceMappingResponse = {
  resourceMapping?: PolicyObjects.ResourceMapping
}

export type UpdateResourceMappingRequest = {
  id?: string
  attributeValueId?: string
  terms?: string[]
  metadata?: CommonCommon.MetadataMutable
  metadataUpdateBehavior?: CommonCommon.MetadataUpdateEnum
}

export type UpdateResourceMappingResponse = {
  resourceMapping?: PolicyObjects.ResourceMapping
}

export type DeleteResourceMappingRequest = {
  id?: string
}

export type DeleteResourceMappingResponse = {
  resourceMapping?: PolicyObjects.ResourceMapping
}

export class ResourceMappingService {
  static ListResourceMappings(req: ListResourceMappingsRequest, initReq?: fm.InitReq): Promise<ListResourceMappingsResponse> {
    return fm.fetchReq<ListResourceMappingsRequest, ListResourceMappingsResponse>(`/resource-mappings?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetResourceMapping(req: GetResourceMappingRequest, initReq?: fm.InitReq): Promise<GetResourceMappingResponse> {
    return fm.fetchReq<GetResourceMappingRequest, GetResourceMappingResponse>(`/resource-mappings/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateResourceMapping(req: CreateResourceMappingRequest, initReq?: fm.InitReq): Promise<CreateResourceMappingResponse> {
    return fm.fetchReq<CreateResourceMappingRequest, CreateResourceMappingResponse>(`/resource-mappings`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateResourceMapping(req: UpdateResourceMappingRequest, initReq?: fm.InitReq): Promise<UpdateResourceMappingResponse> {
    return fm.fetchReq<UpdateResourceMappingRequest, UpdateResourceMappingResponse>(`/resource-mappings/${req["id"]}`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static DeleteResourceMapping(req: DeleteResourceMappingRequest, initReq?: fm.InitReq): Promise<DeleteResourceMappingResponse> {
    return fm.fetchReq<DeleteResourceMappingRequest, DeleteResourceMappingResponse>(`/resource-mappings/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}