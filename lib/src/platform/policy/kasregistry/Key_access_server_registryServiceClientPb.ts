/**
 * @fileoverview gRPC-Web generated client stub for policy.kasregistry
 * @enhanceable
 * @public
 */

// Code generated by protoc-gen-grpc-web. DO NOT EDIT.
// versions:
// 	protoc-gen-grpc-web v1.5.0
// 	protoc              v0.0.0
// source: policy/kasregistry/key_access_server_registry.proto

/* eslint-disable */
// @ts-nocheck

import * as grpcWeb from 'grpc-web';

import * as policy_kasregistry_key_access_server_registry_pb from '../../policy/kasregistry/key_access_server_registry_pb'; // proto import: "policy/kasregistry/key_access_server_registry.proto"

export class KeyAccessServerRegistryServiceClient {
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

  methodDescriptorListKeyAccessServers = new grpcWeb.MethodDescriptor(
    '/policy.kasregistry.KeyAccessServerRegistryService/ListKeyAccessServers',
    grpcWeb.MethodType.UNARY,
    policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersRequest,
    policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersResponse,
    (request: policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersRequest) => {
      return request.serializeBinary();
    },
    policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersResponse.deserializeBinary
  );

  listKeyAccessServers(
    request: policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersRequest,
    metadata?: grpcWeb.Metadata | null
  ): Promise<policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersResponse>;

  listKeyAccessServers(
    request: policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersResponse
    ) => void
  ): grpcWeb.ClientReadableStream<policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersResponse>;

  listKeyAccessServers(
    request: policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersRequest,
    metadata?: grpcWeb.Metadata | null,
    callback?: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.ListKeyAccessServersResponse
    ) => void
  ) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/ListKeyAccessServers',
        request,
        metadata || {},
        this.methodDescriptorListKeyAccessServers,
        callback
      );
    }
    return this.client_.unaryCall(
      this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/ListKeyAccessServers',
      request,
      metadata || {},
      this.methodDescriptorListKeyAccessServers
    );
  }

  methodDescriptorGetKeyAccessServer = new grpcWeb.MethodDescriptor(
    '/policy.kasregistry.KeyAccessServerRegistryService/GetKeyAccessServer',
    grpcWeb.MethodType.UNARY,
    policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerRequest,
    policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerResponse,
    (request: policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerRequest) => {
      return request.serializeBinary();
    },
    policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerResponse.deserializeBinary
  );

  getKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null
  ): Promise<policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerResponse>;

  getKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerResponse
    ) => void
  ): grpcWeb.ClientReadableStream<policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerResponse>;

  getKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null,
    callback?: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.GetKeyAccessServerResponse
    ) => void
  ) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/GetKeyAccessServer',
        request,
        metadata || {},
        this.methodDescriptorGetKeyAccessServer,
        callback
      );
    }
    return this.client_.unaryCall(
      this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/GetKeyAccessServer',
      request,
      metadata || {},
      this.methodDescriptorGetKeyAccessServer
    );
  }

  methodDescriptorCreateKeyAccessServer = new grpcWeb.MethodDescriptor(
    '/policy.kasregistry.KeyAccessServerRegistryService/CreateKeyAccessServer',
    grpcWeb.MethodType.UNARY,
    policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerRequest,
    policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerResponse,
    (request: policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerRequest) => {
      return request.serializeBinary();
    },
    policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerResponse.deserializeBinary
  );

  createKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null
  ): Promise<policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerResponse>;

  createKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerResponse
    ) => void
  ): grpcWeb.ClientReadableStream<policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerResponse>;

  createKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null,
    callback?: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.CreateKeyAccessServerResponse
    ) => void
  ) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/CreateKeyAccessServer',
        request,
        metadata || {},
        this.methodDescriptorCreateKeyAccessServer,
        callback
      );
    }
    return this.client_.unaryCall(
      this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/CreateKeyAccessServer',
      request,
      metadata || {},
      this.methodDescriptorCreateKeyAccessServer
    );
  }

  methodDescriptorUpdateKeyAccessServer = new grpcWeb.MethodDescriptor(
    '/policy.kasregistry.KeyAccessServerRegistryService/UpdateKeyAccessServer',
    grpcWeb.MethodType.UNARY,
    policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerRequest,
    policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerResponse,
    (request: policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerRequest) => {
      return request.serializeBinary();
    },
    policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerResponse.deserializeBinary
  );

  updateKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null
  ): Promise<policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerResponse>;

  updateKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerResponse
    ) => void
  ): grpcWeb.ClientReadableStream<policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerResponse>;

  updateKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null,
    callback?: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.UpdateKeyAccessServerResponse
    ) => void
  ) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/UpdateKeyAccessServer',
        request,
        metadata || {},
        this.methodDescriptorUpdateKeyAccessServer,
        callback
      );
    }
    return this.client_.unaryCall(
      this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/UpdateKeyAccessServer',
      request,
      metadata || {},
      this.methodDescriptorUpdateKeyAccessServer
    );
  }

  methodDescriptorDeleteKeyAccessServer = new grpcWeb.MethodDescriptor(
    '/policy.kasregistry.KeyAccessServerRegistryService/DeleteKeyAccessServer',
    grpcWeb.MethodType.UNARY,
    policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerRequest,
    policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerResponse,
    (request: policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerRequest) => {
      return request.serializeBinary();
    },
    policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerResponse.deserializeBinary
  );

  deleteKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null
  ): Promise<policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerResponse>;

  deleteKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerResponse
    ) => void
  ): grpcWeb.ClientReadableStream<policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerResponse>;

  deleteKeyAccessServer(
    request: policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerRequest,
    metadata?: grpcWeb.Metadata | null,
    callback?: (
      err: grpcWeb.RpcError,
      response: policy_kasregistry_key_access_server_registry_pb.DeleteKeyAccessServerResponse
    ) => void
  ) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/DeleteKeyAccessServer',
        request,
        metadata || {},
        this.methodDescriptorDeleteKeyAccessServer,
        callback
      );
    }
    return this.client_.unaryCall(
      this.hostname_ + '/policy.kasregistry.KeyAccessServerRegistryService/DeleteKeyAccessServer',
      request,
      metadata || {},
      this.methodDescriptorDeleteKeyAccessServer
    );
  }
}
