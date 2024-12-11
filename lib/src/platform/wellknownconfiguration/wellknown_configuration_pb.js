// @generated by protoc-gen-es v1.9.0 with parameter "target=js+dts,import_extension=none"
// @generated from file wellknownconfiguration/wellknown_configuration.proto (package wellknownconfiguration, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { proto3, Struct } from "@bufbuild/protobuf";

/**
 * @generated from message wellknownconfiguration.WellKnownConfig
 */
export const WellKnownConfig = /*@__PURE__*/ proto3.makeMessageType(
  "wellknownconfiguration.WellKnownConfig",
  () => [
    { no: 1, name: "configuration", kind: "map", K: 9 /* ScalarType.STRING */, V: {kind: "message", T: Struct} },
  ],
);

/**
 * @generated from message wellknownconfiguration.GetWellKnownConfigurationRequest
 */
export const GetWellKnownConfigurationRequest = /*@__PURE__*/ proto3.makeMessageType(
  "wellknownconfiguration.GetWellKnownConfigurationRequest",
  [],
);

/**
 * @generated from message wellknownconfiguration.GetWellKnownConfigurationResponse
 */
export const GetWellKnownConfigurationResponse = /*@__PURE__*/ proto3.makeMessageType(
  "wellknownconfiguration.GetWellKnownConfigurationResponse",
  () => [
    { no: 1, name: "configuration", kind: "message", T: Struct },
  ],
);
