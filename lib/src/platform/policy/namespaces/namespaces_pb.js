// @generated by protoc-gen-es v1.9.0 with parameter "target=js+dts,import_extension=none"
// @generated from file policy/namespaces/namespaces.proto (package policy.namespaces, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { proto3 } from "@bufbuild/protobuf";
import { Namespace } from "../objects_pb";
import { ActiveStateEnum, MetadataMutable, MetadataUpdateEnum } from "../../common/common_pb";

/**
 * @generated from message policy.namespaces.GetNamespaceRequest
 */
export const GetNamespaceRequest = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.GetNamespaceRequest",
  () => [
    { no: 1, name: "id", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ],
);

/**
 * @generated from message policy.namespaces.GetNamespaceResponse
 */
export const GetNamespaceResponse = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.GetNamespaceResponse",
  () => [
    { no: 1, name: "namespace", kind: "message", T: Namespace },
  ],
);

/**
 * @generated from message policy.namespaces.ListNamespacesRequest
 */
export const ListNamespacesRequest = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.ListNamespacesRequest",
  () => [
    { no: 1, name: "state", kind: "enum", T: proto3.getEnumType(ActiveStateEnum) },
  ],
);

/**
 * @generated from message policy.namespaces.ListNamespacesResponse
 */
export const ListNamespacesResponse = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.ListNamespacesResponse",
  () => [
    { no: 1, name: "namespaces", kind: "message", T: Namespace, repeated: true },
  ],
);

/**
 * @generated from message policy.namespaces.CreateNamespaceRequest
 */
export const CreateNamespaceRequest = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.CreateNamespaceRequest",
  () => [
    { no: 1, name: "name", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 100, name: "metadata", kind: "message", T: MetadataMutable },
  ],
);

/**
 * @generated from message policy.namespaces.CreateNamespaceResponse
 */
export const CreateNamespaceResponse = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.CreateNamespaceResponse",
  () => [
    { no: 1, name: "namespace", kind: "message", T: Namespace },
  ],
);

/**
 * @generated from message policy.namespaces.UpdateNamespaceRequest
 */
export const UpdateNamespaceRequest = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.UpdateNamespaceRequest",
  () => [
    { no: 1, name: "id", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 100, name: "metadata", kind: "message", T: MetadataMutable },
    { no: 101, name: "metadata_update_behavior", kind: "enum", T: proto3.getEnumType(MetadataUpdateEnum) },
  ],
);

/**
 * @generated from message policy.namespaces.UpdateNamespaceResponse
 */
export const UpdateNamespaceResponse = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.UpdateNamespaceResponse",
  () => [
    { no: 1, name: "namespace", kind: "message", T: Namespace },
  ],
);

/**
 * @generated from message policy.namespaces.DeactivateNamespaceRequest
 */
export const DeactivateNamespaceRequest = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.DeactivateNamespaceRequest",
  () => [
    { no: 1, name: "id", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ],
);

/**
 * @generated from message policy.namespaces.DeactivateNamespaceResponse
 */
export const DeactivateNamespaceResponse = /*@__PURE__*/ proto3.makeMessageType(
  "policy.namespaces.DeactivateNamespaceResponse",
  [],
);
