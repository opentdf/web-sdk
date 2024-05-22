import * as jspb from 'google-protobuf';

import * as google_api_annotations_pb from '../google/api/annotations_pb'; // proto import: "google/api/annotations.proto"
import * as google_protobuf_any_pb from 'google-protobuf/google/protobuf/any_pb'; // proto import: "google/protobuf/any.proto"
import * as policy_objects_pb from '../policy/objects_pb'; // proto import: "policy/objects.proto"

export class Entity extends jspb.Message {
  getId(): string;
  setId(value: string): Entity;

  getEmailAddress(): string;
  setEmailAddress(value: string): Entity;

  getUserName(): string;
  setUserName(value: string): Entity;

  getRemoteClaimsUrl(): string;
  setRemoteClaimsUrl(value: string): Entity;

  getJwt(): string;
  setJwt(value: string): Entity;

  getClaims(): google_protobuf_any_pb.Any | undefined;
  setClaims(value?: google_protobuf_any_pb.Any): Entity;
  hasClaims(): boolean;
  clearClaims(): Entity;

  getCustom(): EntityCustom | undefined;
  setCustom(value?: EntityCustom): Entity;
  hasCustom(): boolean;
  clearCustom(): Entity;

  getClientId(): string;
  setClientId(value: string): Entity;

  getEntityTypeCase(): Entity.EntityTypeCase;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Entity.AsObject;
  static toObject(includeInstance: boolean, msg: Entity): Entity.AsObject;
  static serializeBinaryToWriter(message: Entity, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Entity;
  static deserializeBinaryFromReader(message: Entity, reader: jspb.BinaryReader): Entity;
}

export namespace Entity {
  export type AsObject = {
    id: string;
    emailAddress: string;
    userName: string;
    remoteClaimsUrl: string;
    jwt: string;
    claims?: google_protobuf_any_pb.Any.AsObject;
    custom?: EntityCustom.AsObject;
    clientId: string;
  };

  export enum EntityTypeCase {
    ENTITY_TYPE_NOT_SET = 0,
    EMAIL_ADDRESS = 2,
    USER_NAME = 3,
    REMOTE_CLAIMS_URL = 4,
    JWT = 5,
    CLAIMS = 6,
    CUSTOM = 7,
    CLIENT_ID = 8,
  }
}

export class EntityCustom extends jspb.Message {
  getExtension(): google_protobuf_any_pb.Any | undefined;
  setExtension(value?: google_protobuf_any_pb.Any): EntityCustom;
  hasExtension(): boolean;
  clearExtension(): EntityCustom;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): EntityCustom.AsObject;
  static toObject(includeInstance: boolean, msg: EntityCustom): EntityCustom.AsObject;
  static serializeBinaryToWriter(message: EntityCustom, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): EntityCustom;
  static deserializeBinaryFromReader(
    message: EntityCustom,
    reader: jspb.BinaryReader
  ): EntityCustom;
}

export namespace EntityCustom {
  export type AsObject = {
    extension?: google_protobuf_any_pb.Any.AsObject;
  };
}

export class EntityChain extends jspb.Message {
  getId(): string;
  setId(value: string): EntityChain;

  getEntitiesList(): Array<Entity>;
  setEntitiesList(value: Array<Entity>): EntityChain;
  clearEntitiesList(): EntityChain;
  addEntities(value?: Entity, index?: number): Entity;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): EntityChain.AsObject;
  static toObject(includeInstance: boolean, msg: EntityChain): EntityChain.AsObject;
  static serializeBinaryToWriter(message: EntityChain, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): EntityChain;
  static deserializeBinaryFromReader(message: EntityChain, reader: jspb.BinaryReader): EntityChain;
}

export namespace EntityChain {
  export type AsObject = {
    id: string;
    entitiesList: Array<Entity.AsObject>;
  };
}

export class DecisionRequest extends jspb.Message {
  getActionsList(): Array<policy_objects_pb.Action>;
  setActionsList(value: Array<policy_objects_pb.Action>): DecisionRequest;
  clearActionsList(): DecisionRequest;
  addActions(value?: policy_objects_pb.Action, index?: number): policy_objects_pb.Action;

  getEntityChainsList(): Array<EntityChain>;
  setEntityChainsList(value: Array<EntityChain>): DecisionRequest;
  clearEntityChainsList(): DecisionRequest;
  addEntityChains(value?: EntityChain, index?: number): EntityChain;

  getResourceAttributesList(): Array<ResourceAttribute>;
  setResourceAttributesList(value: Array<ResourceAttribute>): DecisionRequest;
  clearResourceAttributesList(): DecisionRequest;
  addResourceAttributes(value?: ResourceAttribute, index?: number): ResourceAttribute;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DecisionRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DecisionRequest): DecisionRequest.AsObject;
  static serializeBinaryToWriter(message: DecisionRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DecisionRequest;
  static deserializeBinaryFromReader(
    message: DecisionRequest,
    reader: jspb.BinaryReader
  ): DecisionRequest;
}

export namespace DecisionRequest {
  export type AsObject = {
    actionsList: Array<policy_objects_pb.Action.AsObject>;
    entityChainsList: Array<EntityChain.AsObject>;
    resourceAttributesList: Array<ResourceAttribute.AsObject>;
  };
}

export class DecisionResponse extends jspb.Message {
  getEntityChainId(): string;
  setEntityChainId(value: string): DecisionResponse;

  getResourceAttributesId(): string;
  setResourceAttributesId(value: string): DecisionResponse;

  getAction(): policy_objects_pb.Action | undefined;
  setAction(value?: policy_objects_pb.Action): DecisionResponse;
  hasAction(): boolean;
  clearAction(): DecisionResponse;

  getDecision(): DecisionResponse.Decision;
  setDecision(value: DecisionResponse.Decision): DecisionResponse;

  getObligationsList(): Array<string>;
  setObligationsList(value: Array<string>): DecisionResponse;
  clearObligationsList(): DecisionResponse;
  addObligations(value: string, index?: number): DecisionResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DecisionResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DecisionResponse): DecisionResponse.AsObject;
  static serializeBinaryToWriter(message: DecisionResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DecisionResponse;
  static deserializeBinaryFromReader(
    message: DecisionResponse,
    reader: jspb.BinaryReader
  ): DecisionResponse;
}

export namespace DecisionResponse {
  export type AsObject = {
    entityChainId: string;
    resourceAttributesId: string;
    action?: policy_objects_pb.Action.AsObject;
    decision: DecisionResponse.Decision;
    obligationsList: Array<string>;
  };

  export enum Decision {
    DECISION_UNSPECIFIED = 0,
    DECISION_DENY = 1,
    DECISION_PERMIT = 2,
  }
}

export class GetDecisionsRequest extends jspb.Message {
  getDecisionRequestsList(): Array<DecisionRequest>;
  setDecisionRequestsList(value: Array<DecisionRequest>): GetDecisionsRequest;
  clearDecisionRequestsList(): GetDecisionsRequest;
  addDecisionRequests(value?: DecisionRequest, index?: number): DecisionRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetDecisionsRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetDecisionsRequest): GetDecisionsRequest.AsObject;
  static serializeBinaryToWriter(message: GetDecisionsRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetDecisionsRequest;
  static deserializeBinaryFromReader(
    message: GetDecisionsRequest,
    reader: jspb.BinaryReader
  ): GetDecisionsRequest;
}

export namespace GetDecisionsRequest {
  export type AsObject = {
    decisionRequestsList: Array<DecisionRequest.AsObject>;
  };
}

export class GetDecisionsResponse extends jspb.Message {
  getDecisionResponsesList(): Array<DecisionResponse>;
  setDecisionResponsesList(value: Array<DecisionResponse>): GetDecisionsResponse;
  clearDecisionResponsesList(): GetDecisionsResponse;
  addDecisionResponses(value?: DecisionResponse, index?: number): DecisionResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetDecisionsResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetDecisionsResponse
  ): GetDecisionsResponse.AsObject;
  static serializeBinaryToWriter(message: GetDecisionsResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetDecisionsResponse;
  static deserializeBinaryFromReader(
    message: GetDecisionsResponse,
    reader: jspb.BinaryReader
  ): GetDecisionsResponse;
}

export namespace GetDecisionsResponse {
  export type AsObject = {
    decisionResponsesList: Array<DecisionResponse.AsObject>;
  };
}

export class GetEntitlementsRequest extends jspb.Message {
  getEntitiesList(): Array<Entity>;
  setEntitiesList(value: Array<Entity>): GetEntitlementsRequest;
  clearEntitiesList(): GetEntitlementsRequest;
  addEntities(value?: Entity, index?: number): Entity;

  getScope(): ResourceAttribute | undefined;
  setScope(value?: ResourceAttribute): GetEntitlementsRequest;
  hasScope(): boolean;
  clearScope(): GetEntitlementsRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetEntitlementsRequest.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetEntitlementsRequest
  ): GetEntitlementsRequest.AsObject;
  static serializeBinaryToWriter(message: GetEntitlementsRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetEntitlementsRequest;
  static deserializeBinaryFromReader(
    message: GetEntitlementsRequest,
    reader: jspb.BinaryReader
  ): GetEntitlementsRequest;
}

export namespace GetEntitlementsRequest {
  export type AsObject = {
    entitiesList: Array<Entity.AsObject>;
    scope?: ResourceAttribute.AsObject;
  };

  export enum ScopeCase {
    _SCOPE_NOT_SET = 0,
    SCOPE = 2,
  }
}

export class EntityEntitlements extends jspb.Message {
  getEntityId(): string;
  setEntityId(value: string): EntityEntitlements;

  getAttributeValueFqnsList(): Array<string>;
  setAttributeValueFqnsList(value: Array<string>): EntityEntitlements;
  clearAttributeValueFqnsList(): EntityEntitlements;
  addAttributeValueFqns(value: string, index?: number): EntityEntitlements;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): EntityEntitlements.AsObject;
  static toObject(includeInstance: boolean, msg: EntityEntitlements): EntityEntitlements.AsObject;
  static serializeBinaryToWriter(message: EntityEntitlements, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): EntityEntitlements;
  static deserializeBinaryFromReader(
    message: EntityEntitlements,
    reader: jspb.BinaryReader
  ): EntityEntitlements;
}

export namespace EntityEntitlements {
  export type AsObject = {
    entityId: string;
    attributeValueFqnsList: Array<string>;
  };
}

export class ResourceAttribute extends jspb.Message {
  getAttributeValueFqnsList(): Array<string>;
  setAttributeValueFqnsList(value: Array<string>): ResourceAttribute;
  clearAttributeValueFqnsList(): ResourceAttribute;
  addAttributeValueFqns(value: string, index?: number): ResourceAttribute;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ResourceAttribute.AsObject;
  static toObject(includeInstance: boolean, msg: ResourceAttribute): ResourceAttribute.AsObject;
  static serializeBinaryToWriter(message: ResourceAttribute, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ResourceAttribute;
  static deserializeBinaryFromReader(
    message: ResourceAttribute,
    reader: jspb.BinaryReader
  ): ResourceAttribute;
}

export namespace ResourceAttribute {
  export type AsObject = {
    attributeValueFqnsList: Array<string>;
  };
}

export class GetEntitlementsResponse extends jspb.Message {
  getEntitlementsList(): Array<EntityEntitlements>;
  setEntitlementsList(value: Array<EntityEntitlements>): GetEntitlementsResponse;
  clearEntitlementsList(): GetEntitlementsResponse;
  addEntitlements(value?: EntityEntitlements, index?: number): EntityEntitlements;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetEntitlementsResponse.AsObject;
  static toObject(
    includeInstance: boolean,
    msg: GetEntitlementsResponse
  ): GetEntitlementsResponse.AsObject;
  static serializeBinaryToWriter(message: GetEntitlementsResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetEntitlementsResponse;
  static deserializeBinaryFromReader(
    message: GetEntitlementsResponse,
    reader: jspb.BinaryReader
  ): GetEntitlementsResponse;
}

export namespace GetEntitlementsResponse {
  export type AsObject = {
    entitlementsList: Array<EntityEntitlements.AsObject>;
  };
}
