/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as fm from "../fetch.pb"
import * as GoogleProtobufAny from "../google/protobuf/any.pb"
import * as PolicyObjects from "../policy/objects.pb"

type Absent<T, K extends keyof T> = { [k in Exclude<keyof T, K>]?: undefined };
type OneOf<T> =
  | { [k in keyof T]?: undefined }
  | (
    keyof T extends infer K ?
      (K extends string & keyof T ? { [k in K]: T[K] } & Absent<T, K>
        : never)
    : never);

export enum DecisionResponseDecision {
  DECISION_UNSPECIFIED = "DECISION_UNSPECIFIED",
  DECISION_DENY = "DECISION_DENY",
  DECISION_PERMIT = "DECISION_PERMIT",
}


type BaseEntity = {
  id?: string
}

export type Entity = BaseEntity
  & OneOf<{ emailAddress: string; userName: string; remoteClaimsUrl: string; jwt: string; claims: GoogleProtobufAny.Any; custom: EntityCustom; clientId: string }>

export type EntityCustom = {
  extension?: GoogleProtobufAny.Any
}

export type EntityChain = {
  id?: string
  entities?: Entity[]
}

export type DecisionRequest = {
  actions?: PolicyObjects.Action[]
  entityChains?: EntityChain[]
  resourceAttributes?: ResourceAttribute[]
}

export type DecisionResponse = {
  entityChainId?: string
  resourceAttributesId?: string
  action?: PolicyObjects.Action
  decision?: DecisionResponseDecision
  obligations?: string[]
}

export type GetDecisionsRequest = {
  decisionRequests?: DecisionRequest[]
}

export type GetDecisionsResponse = {
  decisionResponses?: DecisionResponse[]
}


type BaseGetEntitlementsRequest = {
  entities?: Entity[]
}

export type GetEntitlementsRequest = BaseGetEntitlementsRequest
  & OneOf<{ scope: ResourceAttribute }>

export type EntityEntitlements = {
  entityId?: string
  attributeValueFqns?: string[]
}

export type ResourceAttribute = {
  attributeValueFqns?: string[]
}

export type GetEntitlementsResponse = {
  entitlements?: EntityEntitlements[]
}

export class AuthorizationService {
  static GetDecisions(req: GetDecisionsRequest, initReq?: fm.InitReq): Promise<GetDecisionsResponse> {
    return fm.fetchReq<GetDecisionsRequest, GetDecisionsResponse>(`/v1/authorization`, {...initReq, method: "POST"})
  }
  static GetEntitlements(req: GetEntitlementsRequest, initReq?: fm.InitReq): Promise<GetEntitlementsResponse> {
    return fm.fetchReq<GetEntitlementsRequest, GetEntitlementsResponse>(`/v1/entitlements`, {...initReq, method: "POST"})
  }
}