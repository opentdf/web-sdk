// @generated by protoc-gen-connect-es v1.4.0 with parameter "target=ts"
// @generated from file authorization/authorization.proto (package authorization, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { GetDecisionsRequest, GetDecisionsResponse, GetEntitlementsRequest, GetEntitlementsResponse } from "./authorization_pb.js";
import { MethodKind } from "@bufbuild/protobuf";

/**
 * @generated from service authorization.AuthorizationService
 */
export const AuthorizationService = {
  typeName: "authorization.AuthorizationService",
  methods: {
    /**
     * @generated from rpc authorization.AuthorizationService.GetDecisions
     */
    getDecisions: {
      name: "GetDecisions",
      I: GetDecisionsRequest,
      O: GetDecisionsResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc authorization.AuthorizationService.GetEntitlements
     */
    getEntitlements: {
      name: "GetEntitlements",
      I: GetEntitlementsRequest,
      O: GetEntitlementsResponse,
      kind: MethodKind.Unary,
    },
  }
} as const;
