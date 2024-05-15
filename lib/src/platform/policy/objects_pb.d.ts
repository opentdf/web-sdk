import * as jspb from 'google-protobuf';

import * as buf_validate_validate_pb from '../buf/validate/validate_pb'; // proto import: "buf/validate/validate.proto"
import * as common_common_pb from '../common/common_pb'; // proto import: "common/common.proto"
import * as google_protobuf_wrappers_pb from 'google-protobuf/google/protobuf/wrappers_pb'; // proto import: "google/protobuf/wrappers.proto"

export class Namespace extends jspb.Message {
  getId(): string;
  setId(value: string): Namespace;

  getName(): string;
  setName(value: string): Namespace;

  getFqn(): string;
  setFqn(value: string): Namespace;

  getActive(): google_protobuf_wrappers_pb.BoolValue | undefined;
  setActive(value?: google_protobuf_wrappers_pb.BoolValue): Namespace;
  hasActive(): boolean;
  clearActive(): Namespace;

  getMetadata(): common_common_pb.Metadata | undefined;
  setMetadata(value?: common_common_pb.Metadata): Namespace;
  hasMetadata(): boolean;
  clearMetadata(): Namespace;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Namespace.AsObject;
  static toObject(includeInstance: boolean, msg: Namespace): Namespace.AsObject;
  static serializeBinaryToWriter(message: Namespace, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Namespace;
  static deserializeBinaryFromReader(message: Namespace, reader: jspb.BinaryReader): Namespace;
}

export namespace Namespace {
  export type AsObject = {
    id: string;
    name: string;
    fqn: string;
    active?: google_protobuf_wrappers_pb.BoolValue.AsObject;
    metadata?: common_common_pb.Metadata.AsObject;
  };
}

export class Attribute extends jspb.Message {
  getId(): string;
  setId(value: string): Attribute;

  getNamespace(): Namespace | undefined;
  setNamespace(value?: Namespace): Attribute;
  hasNamespace(): boolean;
  clearNamespace(): Attribute;

  getName(): string;
  setName(value: string): Attribute;

  getRule(): AttributeRuleTypeEnum;
  setRule(value: AttributeRuleTypeEnum): Attribute;

  getValuesList(): Array<Value>;
  setValuesList(value: Array<Value>): Attribute;
  clearValuesList(): Attribute;
  addValues(value?: Value, index?: number): Value;

  getGrantsList(): Array<KeyAccessServer>;
  setGrantsList(value: Array<KeyAccessServer>): Attribute;
  clearGrantsList(): Attribute;
  addGrants(value?: KeyAccessServer, index?: number): KeyAccessServer;

  getFqn(): string;
  setFqn(value: string): Attribute;

  getActive(): google_protobuf_wrappers_pb.BoolValue | undefined;
  setActive(value?: google_protobuf_wrappers_pb.BoolValue): Attribute;
  hasActive(): boolean;
  clearActive(): Attribute;

  getMetadata(): common_common_pb.Metadata | undefined;
  setMetadata(value?: common_common_pb.Metadata): Attribute;
  hasMetadata(): boolean;
  clearMetadata(): Attribute;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Attribute.AsObject;
  static toObject(includeInstance: boolean, msg: Attribute): Attribute.AsObject;
  static serializeBinaryToWriter(message: Attribute, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Attribute;
  static deserializeBinaryFromReader(message: Attribute, reader: jspb.BinaryReader): Attribute;
}

export namespace Attribute {
  export type AsObject = {
    id: string;
    namespace?: Namespace.AsObject;
    name: string;
    rule: AttributeRuleTypeEnum;
    valuesList: Array<Value.AsObject>;
    grantsList: Array<KeyAccessServer.AsObject>;
    fqn: string;
    active?: google_protobuf_wrappers_pb.BoolValue.AsObject;
    metadata?: common_common_pb.Metadata.AsObject;
  };
}

export class Value extends jspb.Message {
  getId(): string;
  setId(value: string): Value;

  getAttribute(): Attribute | undefined;
  setAttribute(value?: Attribute): Value;
  hasAttribute(): boolean;
  clearAttribute(): Value;

  getValue(): string;
  setValue(value: string): Value;

  getMembersList(): Array<Value>;
  setMembersList(value: Array<Value>): Value;
  clearMembersList(): Value;
  addMembers(value?: Value, index?: number): Value;

  getGrantsList(): Array<KeyAccessServer>;
  setGrantsList(value: Array<KeyAccessServer>): Value;
  clearGrantsList(): Value;
  addGrants(value?: KeyAccessServer, index?: number): KeyAccessServer;

  getFqn(): string;
  setFqn(value: string): Value;

  getActive(): google_protobuf_wrappers_pb.BoolValue | undefined;
  setActive(value?: google_protobuf_wrappers_pb.BoolValue): Value;
  hasActive(): boolean;
  clearActive(): Value;

  getSubjectMappingsList(): Array<SubjectMapping>;
  setSubjectMappingsList(value: Array<SubjectMapping>): Value;
  clearSubjectMappingsList(): Value;
  addSubjectMappings(value?: SubjectMapping, index?: number): SubjectMapping;

  getMetadata(): common_common_pb.Metadata | undefined;
  setMetadata(value?: common_common_pb.Metadata): Value;
  hasMetadata(): boolean;
  clearMetadata(): Value;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Value.AsObject;
  static toObject(includeInstance: boolean, msg: Value): Value.AsObject;
  static serializeBinaryToWriter(message: Value, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Value;
  static deserializeBinaryFromReader(message: Value, reader: jspb.BinaryReader): Value;
}

export namespace Value {
  export type AsObject = {
    id: string;
    attribute?: Attribute.AsObject;
    value: string;
    membersList: Array<Value.AsObject>;
    grantsList: Array<KeyAccessServer.AsObject>;
    fqn: string;
    active?: google_protobuf_wrappers_pb.BoolValue.AsObject;
    subjectMappingsList: Array<SubjectMapping.AsObject>;
    metadata?: common_common_pb.Metadata.AsObject;
  };
}

export class Action extends jspb.Message {
  getStandard(): Action.StandardAction;
  setStandard(value: Action.StandardAction): Action;

  getCustom(): string;
  setCustom(value: string): Action;

  getValueCase(): Action.ValueCase;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Action.AsObject;
  static toObject(includeInstance: boolean, msg: Action): Action.AsObject;
  static serializeBinaryToWriter(message: Action, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Action;
  static deserializeBinaryFromReader(message: Action, reader: jspb.BinaryReader): Action;
}

export namespace Action {
  export type AsObject = {
    standard: Action.StandardAction;
    custom: string;
  };

  export enum StandardAction {
    STANDARD_ACTION_UNSPECIFIED = 0,
    STANDARD_ACTION_DECRYPT = 1,
    STANDARD_ACTION_TRANSMIT = 2,
  }

  export enum ValueCase {
    VALUE_NOT_SET = 0,
    STANDARD = 1,
    CUSTOM = 2,
  }
}

export class SubjectMapping extends jspb.Message {
  getId(): string;
  setId(value: string): SubjectMapping;

  getAttributeValue(): Value | undefined;
  setAttributeValue(value?: Value): SubjectMapping;
  hasAttributeValue(): boolean;
  clearAttributeValue(): SubjectMapping;

  getSubjectConditionSet(): SubjectConditionSet | undefined;
  setSubjectConditionSet(value?: SubjectConditionSet): SubjectMapping;
  hasSubjectConditionSet(): boolean;
  clearSubjectConditionSet(): SubjectMapping;

  getActionsList(): Array<Action>;
  setActionsList(value: Array<Action>): SubjectMapping;
  clearActionsList(): SubjectMapping;
  addActions(value?: Action, index?: number): Action;

  getMetadata(): common_common_pb.Metadata | undefined;
  setMetadata(value?: common_common_pb.Metadata): SubjectMapping;
  hasMetadata(): boolean;
  clearMetadata(): SubjectMapping;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): SubjectMapping.AsObject;
  static toObject(includeInstance: boolean, msg: SubjectMapping): SubjectMapping.AsObject;
  static serializeBinaryToWriter(message: SubjectMapping, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): SubjectMapping;
  static deserializeBinaryFromReader(
    message: SubjectMapping,
    reader: jspb.BinaryReader
  ): SubjectMapping;
}

export namespace SubjectMapping {
  export type AsObject = {
    id: string;
    attributeValue?: Value.AsObject;
    subjectConditionSet?: SubjectConditionSet.AsObject;
    actionsList: Array<Action.AsObject>;
    metadata?: common_common_pb.Metadata.AsObject;
  };
}

export class Condition extends jspb.Message {
  getSubjectExternalSelectorValue(): string;
  setSubjectExternalSelectorValue(value: string): Condition;

  getOperator(): SubjectMappingOperatorEnum;
  setOperator(value: SubjectMappingOperatorEnum): Condition;

  getSubjectExternalValuesList(): Array<string>;
  setSubjectExternalValuesList(value: Array<string>): Condition;
  clearSubjectExternalValuesList(): Condition;
  addSubjectExternalValues(value: string, index?: number): Condition;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Condition.AsObject;
  static toObject(includeInstance: boolean, msg: Condition): Condition.AsObject;
  static serializeBinaryToWriter(message: Condition, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Condition;
  static deserializeBinaryFromReader(message: Condition, reader: jspb.BinaryReader): Condition;
}

export namespace Condition {
  export type AsObject = {
    subjectExternalSelectorValue: string;
    operator: SubjectMappingOperatorEnum;
    subjectExternalValuesList: Array<string>;
  };
}

export class ConditionGroup extends jspb.Message {
  getConditionsList(): Array<Condition>;
  setConditionsList(value: Array<Condition>): ConditionGroup;
  clearConditionsList(): ConditionGroup;
  addConditions(value?: Condition, index?: number): Condition;

  getBooleanOperator(): ConditionBooleanTypeEnum;
  setBooleanOperator(value: ConditionBooleanTypeEnum): ConditionGroup;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ConditionGroup.AsObject;
  static toObject(includeInstance: boolean, msg: ConditionGroup): ConditionGroup.AsObject;
  static serializeBinaryToWriter(message: ConditionGroup, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ConditionGroup;
  static deserializeBinaryFromReader(
    message: ConditionGroup,
    reader: jspb.BinaryReader
  ): ConditionGroup;
}

export namespace ConditionGroup {
  export type AsObject = {
    conditionsList: Array<Condition.AsObject>;
    booleanOperator: ConditionBooleanTypeEnum;
  };
}

export class SubjectSet extends jspb.Message {
  getConditionGroupsList(): Array<ConditionGroup>;
  setConditionGroupsList(value: Array<ConditionGroup>): SubjectSet;
  clearConditionGroupsList(): SubjectSet;
  addConditionGroups(value?: ConditionGroup, index?: number): ConditionGroup;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): SubjectSet.AsObject;
  static toObject(includeInstance: boolean, msg: SubjectSet): SubjectSet.AsObject;
  static serializeBinaryToWriter(message: SubjectSet, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): SubjectSet;
  static deserializeBinaryFromReader(message: SubjectSet, reader: jspb.BinaryReader): SubjectSet;
}

export namespace SubjectSet {
  export type AsObject = {
    conditionGroupsList: Array<ConditionGroup.AsObject>;
  };
}

export class SubjectConditionSet extends jspb.Message {
  getId(): string;
  setId(value: string): SubjectConditionSet;

  getSubjectSetsList(): Array<SubjectSet>;
  setSubjectSetsList(value: Array<SubjectSet>): SubjectConditionSet;
  clearSubjectSetsList(): SubjectConditionSet;
  addSubjectSets(value?: SubjectSet, index?: number): SubjectSet;

  getMetadata(): common_common_pb.Metadata | undefined;
  setMetadata(value?: common_common_pb.Metadata): SubjectConditionSet;
  hasMetadata(): boolean;
  clearMetadata(): SubjectConditionSet;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): SubjectConditionSet.AsObject;
  static toObject(includeInstance: boolean, msg: SubjectConditionSet): SubjectConditionSet.AsObject;
  static serializeBinaryToWriter(message: SubjectConditionSet, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): SubjectConditionSet;
  static deserializeBinaryFromReader(
    message: SubjectConditionSet,
    reader: jspb.BinaryReader
  ): SubjectConditionSet;
}

export namespace SubjectConditionSet {
  export type AsObject = {
    id: string;
    subjectSetsList: Array<SubjectSet.AsObject>;
    metadata?: common_common_pb.Metadata.AsObject;
  };
}

export class SubjectProperty extends jspb.Message {
  getExternalSelectorValue(): string;
  setExternalSelectorValue(value: string): SubjectProperty;

  getExternalValue(): string;
  setExternalValue(value: string): SubjectProperty;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): SubjectProperty.AsObject;
  static toObject(includeInstance: boolean, msg: SubjectProperty): SubjectProperty.AsObject;
  static serializeBinaryToWriter(message: SubjectProperty, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): SubjectProperty;
  static deserializeBinaryFromReader(
    message: SubjectProperty,
    reader: jspb.BinaryReader
  ): SubjectProperty;
}

export namespace SubjectProperty {
  export type AsObject = {
    externalSelectorValue: string;
    externalValue: string;
  };
}

export class ResourceMapping extends jspb.Message {
  getId(): string;
  setId(value: string): ResourceMapping;

  getMetadata(): common_common_pb.Metadata | undefined;
  setMetadata(value?: common_common_pb.Metadata): ResourceMapping;
  hasMetadata(): boolean;
  clearMetadata(): ResourceMapping;

  getAttributeValue(): Value | undefined;
  setAttributeValue(value?: Value): ResourceMapping;
  hasAttributeValue(): boolean;
  clearAttributeValue(): ResourceMapping;

  getTermsList(): Array<string>;
  setTermsList(value: Array<string>): ResourceMapping;
  clearTermsList(): ResourceMapping;
  addTerms(value: string, index?: number): ResourceMapping;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ResourceMapping.AsObject;
  static toObject(includeInstance: boolean, msg: ResourceMapping): ResourceMapping.AsObject;
  static serializeBinaryToWriter(message: ResourceMapping, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ResourceMapping;
  static deserializeBinaryFromReader(
    message: ResourceMapping,
    reader: jspb.BinaryReader
  ): ResourceMapping;
}

export namespace ResourceMapping {
  export type AsObject = {
    id: string;
    metadata?: common_common_pb.Metadata.AsObject;
    attributeValue?: Value.AsObject;
    termsList: Array<string>;
  };
}

export class KeyAccessServer extends jspb.Message {
  getId(): string;
  setId(value: string): KeyAccessServer;

  getUri(): string;
  setUri(value: string): KeyAccessServer;

  getPublicKey(): PublicKey | undefined;
  setPublicKey(value?: PublicKey): KeyAccessServer;
  hasPublicKey(): boolean;
  clearPublicKey(): KeyAccessServer;

  getMetadata(): common_common_pb.Metadata | undefined;
  setMetadata(value?: common_common_pb.Metadata): KeyAccessServer;
  hasMetadata(): boolean;
  clearMetadata(): KeyAccessServer;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): KeyAccessServer.AsObject;
  static toObject(includeInstance: boolean, msg: KeyAccessServer): KeyAccessServer.AsObject;
  static serializeBinaryToWriter(message: KeyAccessServer, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): KeyAccessServer;
  static deserializeBinaryFromReader(
    message: KeyAccessServer,
    reader: jspb.BinaryReader
  ): KeyAccessServer;
}

export namespace KeyAccessServer {
  export type AsObject = {
    id: string;
    uri: string;
    publicKey?: PublicKey.AsObject;
    metadata?: common_common_pb.Metadata.AsObject;
  };
}

export class PublicKey extends jspb.Message {
  getRemote(): string;
  setRemote(value: string): PublicKey;

  getLocal(): string;
  setLocal(value: string): PublicKey;

  getPublicKeyCase(): PublicKey.PublicKeyCase;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): PublicKey.AsObject;
  static toObject(includeInstance: boolean, msg: PublicKey): PublicKey.AsObject;
  static serializeBinaryToWriter(message: PublicKey, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): PublicKey;
  static deserializeBinaryFromReader(message: PublicKey, reader: jspb.BinaryReader): PublicKey;
}

export namespace PublicKey {
  export type AsObject = {
    remote: string;
    local: string;
  };

  export enum PublicKeyCase {
    PUBLIC_KEY_NOT_SET = 0,
    REMOTE = 1,
    LOCAL = 2,
  }
}

export enum AttributeRuleTypeEnum {
  ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED = 0,
  ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF = 1,
  ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF = 2,
  ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY = 3,
}
export enum SubjectMappingOperatorEnum {
  SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED = 0,
  SUBJECT_MAPPING_OPERATOR_ENUM_IN = 1,
  SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN = 2,
}
export enum ConditionBooleanTypeEnum {
  CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED = 0,
  CONDITION_BOOLEAN_TYPE_ENUM_AND = 1,
  CONDITION_BOOLEAN_TYPE_ENUM_OR = 2,
}
