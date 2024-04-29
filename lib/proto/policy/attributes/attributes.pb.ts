/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as CommonCommon from "../../common/common.pb"
import * as fm from "../../fetch.pb"
import * as PolicyObjects from "../objects.pb"
import * as PolicySelectors from "../selectors.pb"
export type AttributeKeyAccessServer = {
  attributeId?: string
  keyAccessServerId?: string
}

export type ValueKeyAccessServer = {
  valueId?: string
  keyAccessServerId?: string
}

export type ListAttributesRequest = {
  state?: CommonCommon.ActiveStateEnum
  namespace?: string
}

export type ListAttributesResponse = {
  attributes?: PolicyObjects.Attribute[]
}

export type GetAttributeRequest = {
  id?: string
}

export type GetAttributeResponse = {
  attribute?: PolicyObjects.Attribute
}

export type CreateAttributeRequest = {
  namespaceId?: string
  name?: string
  rule?: PolicyObjects.AttributeRuleTypeEnum
  values?: string[]
  metadata?: CommonCommon.MetadataMutable
}

export type CreateAttributeResponse = {
  attribute?: PolicyObjects.Attribute
}

export type UpdateAttributeRequest = {
  id?: string
  metadata?: CommonCommon.MetadataMutable
  metadataUpdateBehavior?: CommonCommon.MetadataUpdateEnum
}

export type UpdateAttributeResponse = {
  attribute?: PolicyObjects.Attribute
}

export type DeactivateAttributeRequest = {
  id?: string
}

export type DeactivateAttributeResponse = {
  attribute?: PolicyObjects.Attribute
}

export type GetAttributeValueRequest = {
  id?: string
}

export type GetAttributeValueResponse = {
  value?: PolicyObjects.Value
}

export type ListAttributeValuesRequest = {
  attributeId?: string
  state?: CommonCommon.ActiveStateEnum
}

export type ListAttributeValuesResponse = {
  values?: PolicyObjects.Value[]
}

export type CreateAttributeValueRequest = {
  attributeId?: string
  value?: string
  members?: string[]
  metadata?: CommonCommon.MetadataMutable
}

export type CreateAttributeValueResponse = {
  value?: PolicyObjects.Value
}

export type UpdateAttributeValueRequest = {
  id?: string
  members?: string[]
  metadata?: CommonCommon.MetadataMutable
  metadataUpdateBehavior?: CommonCommon.MetadataUpdateEnum
}

export type UpdateAttributeValueResponse = {
  value?: PolicyObjects.Value
}

export type DeactivateAttributeValueRequest = {
  id?: string
}

export type DeactivateAttributeValueResponse = {
  value?: PolicyObjects.Value
}

export type GetAttributeValuesByFqnsRequest = {
  fqns?: string[]
  withValue?: PolicySelectors.AttributeValueSelector
}

export type GetAttributeValuesByFqnsResponseAttributeAndValue = {
  attribute?: PolicyObjects.Attribute
  value?: PolicyObjects.Value
}

export type GetAttributeValuesByFqnsResponse = {
  fqnAttributeValues?: {[key: string]: GetAttributeValuesByFqnsResponseAttributeAndValue}
}

export type AssignKeyAccessServerToAttributeRequest = {
  attributeKeyAccessServer?: AttributeKeyAccessServer
}

export type AssignKeyAccessServerToAttributeResponse = {
  attributeKeyAccessServer?: AttributeKeyAccessServer
}

export type RemoveKeyAccessServerFromAttributeRequest = {
  attributeKeyAccessServer?: AttributeKeyAccessServer
}

export type RemoveKeyAccessServerFromAttributeResponse = {
  attributeKeyAccessServer?: AttributeKeyAccessServer
}

export type AssignKeyAccessServerToValueRequest = {
  valueKeyAccessServer?: ValueKeyAccessServer
}

export type AssignKeyAccessServerToValueResponse = {
  valueKeyAccessServer?: ValueKeyAccessServer
}

export type RemoveKeyAccessServerFromValueRequest = {
  valueKeyAccessServer?: ValueKeyAccessServer
}

export type RemoveKeyAccessServerFromValueResponse = {
  valueKeyAccessServer?: ValueKeyAccessServer
}

export class AttributesService {
  static ListAttributes(req: ListAttributesRequest, initReq?: fm.InitReq): Promise<ListAttributesResponse> {
    return fm.fetchReq<ListAttributesRequest, ListAttributesResponse>(`/attributes?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static ListAttributeValues(req: ListAttributeValuesRequest, initReq?: fm.InitReq): Promise<ListAttributeValuesResponse> {
    return fm.fetchReq<ListAttributeValuesRequest, ListAttributeValuesResponse>(`/attributes/*/values?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetAttribute(req: GetAttributeRequest, initReq?: fm.InitReq): Promise<GetAttributeResponse> {
    return fm.fetchReq<GetAttributeRequest, GetAttributeResponse>(`/attributes/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static GetAttributeValuesByFqns(req: GetAttributeValuesByFqnsRequest, initReq?: fm.InitReq): Promise<GetAttributeValuesByFqnsResponse> {
    return fm.fetchReq<GetAttributeValuesByFqnsRequest, GetAttributeValuesByFqnsResponse>(`/attributes/*/fqn?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static CreateAttribute(req: CreateAttributeRequest, initReq?: fm.InitReq): Promise<CreateAttributeResponse> {
    return fm.fetchReq<CreateAttributeRequest, CreateAttributeResponse>(`/attributes`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateAttribute(req: UpdateAttributeRequest, initReq?: fm.InitReq): Promise<UpdateAttributeResponse> {
    return fm.fetchReq<UpdateAttributeRequest, UpdateAttributeResponse>(`/attributes/${req["id"]}`, {...initReq, method: "PATCH", body: JSON.stringify(req, fm.replacer)})
  }
  static DeactivateAttribute(req: DeactivateAttributeRequest, initReq?: fm.InitReq): Promise<DeactivateAttributeResponse> {
    return fm.fetchReq<DeactivateAttributeRequest, DeactivateAttributeResponse>(`/attributes/${req["id"]}`, {...initReq, method: "DELETE"})
  }
  static GetAttributeValue(req: GetAttributeValueRequest, initReq?: fm.InitReq): Promise<GetAttributeValueResponse> {
    return fm.fetchReq<GetAttributeValueRequest, GetAttributeValueResponse>(`/attributes/*/values/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateAttributeValue(req: CreateAttributeValueRequest, initReq?: fm.InitReq): Promise<CreateAttributeValueResponse> {
    return fm.fetchReq<CreateAttributeValueRequest, CreateAttributeValueResponse>(`/attributes/${req["attributeId"]}/values`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateAttributeValue(req: UpdateAttributeValueRequest, initReq?: fm.InitReq): Promise<UpdateAttributeValueResponse> {
    return fm.fetchReq<UpdateAttributeValueRequest, UpdateAttributeValueResponse>(`/attributes/*/values/${req["id"]}`, {...initReq, method: "PATCH", body: JSON.stringify(req, fm.replacer)})
  }
  static DeactivateAttributeValue(req: DeactivateAttributeValueRequest, initReq?: fm.InitReq): Promise<DeactivateAttributeValueResponse> {
    return fm.fetchReq<DeactivateAttributeValueRequest, DeactivateAttributeValueResponse>(`/attributes/*/values/${req["id"]}`, {...initReq, method: "DELETE"})
  }
  static AssignKeyAccessServerToAttribute(req: AssignKeyAccessServerToAttributeRequest, initReq?: fm.InitReq): Promise<AssignKeyAccessServerToAttributeResponse> {
    return fm.fetchReq<AssignKeyAccessServerToAttributeRequest, AssignKeyAccessServerToAttributeResponse>(`/attributes/keyaccessserver/assign`, {...initReq, method: "POST", body: JSON.stringify(req["attribute_key_access_server"], fm.replacer)})
  }
  static RemoveKeyAccessServerFromAttribute(req: RemoveKeyAccessServerFromAttributeRequest, initReq?: fm.InitReq): Promise<RemoveKeyAccessServerFromAttributeResponse> {
    return fm.fetchReq<RemoveKeyAccessServerFromAttributeRequest, RemoveKeyAccessServerFromAttributeResponse>(`/attributes/keyaccessserver/remove`, {...initReq, method: "POST", body: JSON.stringify(req["attribute_key_access_server"], fm.replacer)})
  }
  static AssignKeyAccessServerToValue(req: AssignKeyAccessServerToValueRequest, initReq?: fm.InitReq): Promise<AssignKeyAccessServerToValueResponse> {
    return fm.fetchReq<AssignKeyAccessServerToValueRequest, AssignKeyAccessServerToValueResponse>(`/attributes/values/keyaccessserver/assign`, {...initReq, method: "POST", body: JSON.stringify(req["value_key_access_server"], fm.replacer)})
  }
  static RemoveKeyAccessServerFromValue(req: RemoveKeyAccessServerFromValueRequest, initReq?: fm.InitReq): Promise<RemoveKeyAccessServerFromValueResponse> {
    return fm.fetchReq<RemoveKeyAccessServerFromValueRequest, RemoveKeyAccessServerFromValueResponse>(`/attributes/values/keyaccessserver/remove`, {...initReq, method: "POST", body: JSON.stringify(req["value_key_access_server"], fm.replacer)})
  }
}