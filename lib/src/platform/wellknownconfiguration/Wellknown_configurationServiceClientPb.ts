/**
 * @fileoverview gRPC-Web generated client stub for wellknownconfiguration
 * @enhanceable
 * @public
 */

// Code generated by protoc-gen-grpc-web. DO NOT EDIT.
// versions:
// 	protoc-gen-grpc-web v1.5.0
// 	protoc              v0.0.0
// source: wellknownconfiguration/wellknown_configuration.proto

/* eslint-disable */
// @ts-nocheck

import * as grpcWeb from 'grpc-web';

import * as wellknownconfiguration_wellknown_configuration_pb from '../wellknownconfiguration/wellknown_configuration_pb'; // proto import: "wellknownconfiguration/wellknown_configuration.proto"

export class WellKnownServiceClient {
  client_: grpcWeb.AbstractClientBase;
  hostname_: string;
  credentials_: null | { [index: string]: string };
  options_: null | { [index: string]: any };

  constructor(
    hostname: string,
    credentials?: null | { [index: string]: string },
    options?: null | { [index: string]: any }
  ) {
    if (!options) options = {};
    if (!credentials) credentials = {};
    options['format'] = 'binary';

    this.client_ = new grpcWeb.GrpcWebClientBase(options);
    this.hostname_ = hostname.replace(/\/+$/, '');
    this.credentials_ = credentials;
    this.options_ = options;
  }

  methodDescriptorGetWellKnownConfiguration = new grpcWeb.MethodDescriptor(
    '/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration',
    grpcWeb.MethodType.UNARY,
    wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationRequest,
    wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationResponse,
    (
      request: wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationRequest
    ) => {
      return request.serializeBinary();
    },
    wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationResponse.deserializeBinary
  );

  getWellKnownConfiguration(
    request: wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationRequest,
    metadata?: grpcWeb.Metadata | null
  ): Promise<wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationResponse>;

  getWellKnownConfiguration(
    request: wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (
      err: grpcWeb.RpcError,
      response: wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationResponse
    ) => void
  ): grpcWeb.ClientReadableStream<wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationResponse>;

  getWellKnownConfiguration(
    request: wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationRequest,
    metadata?: grpcWeb.Metadata | null,
    callback?: (
      err: grpcWeb.RpcError,
      response: wellknownconfiguration_wellknown_configuration_pb.GetWellKnownConfigurationResponse
    ) => void
  ) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ + '/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration',
        request,
        metadata || {},
        this.methodDescriptorGetWellKnownConfiguration,
        callback
      );
    }
    return this.client_.unaryCall(
      this.hostname_ + '/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration',
      request,
      metadata || {},
      this.methodDescriptorGetWellKnownConfiguration
    );
  }
}