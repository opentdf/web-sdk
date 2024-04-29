/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as CommonCommon from "../common/common.pb"
import * as GoogleProtobufWrappers from "../google/protobuf/wrappers.pb"

type Absent<T, K extends keyof T> = { [k in Exclude<keyof T, K>]?: undefined };
type OneOf<T> =
  | { [k in keyof T]?: undefined }
  | (
    keyof T extends infer K ?
      (K extends string & keyof T ? { [k in K]: T[K] } & Absent<T, K>
        : never)
    : never);

export enum AttributeRuleTypeEnum {
  ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED = "ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED",
  ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF = "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
  ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF = "ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF",
  ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY = "ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY",
}

export enum SubjectMappingOperatorEnum {
  SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED = "SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED",
  SUBJECT_MAPPING_OPERATOR_ENUM_IN = "SUBJECT_MAPPING_OPERATOR_ENUM_IN",
  SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN = "SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN",
}

export enum ConditionBooleanTypeEnum {
  CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED = "CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED",
  CONDITION_BOOLEAN_TYPE_ENUM_AND = "CONDITION_BOOLEAN_TYPE_ENUM_AND",
  CONDITION_BOOLEAN_TYPE_ENUM_OR = "CONDITION_BOOLEAN_TYPE_ENUM_OR",
}

export enum ActionStandardAction {
  STANDARD_ACTION_UNSPECIFIED = "STANDARD_ACTION_UNSPECIFIED",
  STANDARD_ACTION_DECRYPT = "STANDARD_ACTION_DECRYPT",
  STANDARD_ACTION_TRANSMIT = "STANDARD_ACTION_TRANSMIT",
}

export type Namespace = {
  id?: string
  name?: string
  fqn?: string
  active?: GoogleProtobufWrappers.BoolValue
  metadata?: CommonCommon.Metadata
}

export type Attribute = {
  id?: string
  namespace?: Namespace
  name?: string
  rule?: AttributeRuleTypeEnum
  values?: Value[]
  grants?: KeyAccessServer[]
  fqn?: string
  active?: GoogleProtobufWrappers.BoolValue
  metadata?: CommonCommon.Metadata
}

export type Value = {
  id?: string
  attribute?: Attribute
  value?: string
  members?: Value[]
  grants?: KeyAccessServer[]
  fqn?: string
  active?: GoogleProtobufWrappers.BoolValue
  subjectMappings?: SubjectMapping[]
  metadata?: CommonCommon.Metadata
}


type BaseAction = {
}

export type Action = BaseAction
  & OneOf<{ standard: ActionStandardAction; custom: string }>

export type SubjectMapping = {
  id?: string
  attributeValue?: Value
  subjectConditionSet?: SubjectConditionSet
  actions?: Action[]
  metadata?: CommonCommon.Metadata
}

export type Condition = {
  subjectExternalSelectorValue?: string
  operator?: SubjectMappingOperatorEnum
  subjectExternalValues?: string[]
}

export type ConditionGroup = {
  conditions?: Condition[]
  booleanOperator?: ConditionBooleanTypeEnum
}

export type SubjectSet = {
  conditionGroups?: ConditionGroup[]
}

export type SubjectConditionSet = {
  id?: string
  subjectSets?: SubjectSet[]
  metadata?: CommonCommon.Metadata
}

export type SubjectProperty = {
  externalSelectorValue?: string
  externalValue?: string
}

export type ResourceMapping = {
  id?: string
  metadata?: CommonCommon.Metadata
  attributeValue?: Value
  terms?: string[]
}

export type KeyAccessServer = {
  id?: string
  uri?: string
  publicKey?: PublicKey
  metadata?: CommonCommon.Metadata
}


type BasePublicKey = {
}

export type PublicKey = BasePublicKey
  & OneOf<{ remote: string; local: string }>