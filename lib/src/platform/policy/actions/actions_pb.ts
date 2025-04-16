// @generated by protoc-gen-es v2.2.5 with parameter "target=ts,import_extension=.js"
// @generated from file policy/actions/actions.proto (package policy.actions, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage, GenService } from "@bufbuild/protobuf/codegenv1";
import { fileDesc, messageDesc, serviceDesc } from "@bufbuild/protobuf/codegenv1";
import { file_buf_validate_validate } from "../../buf/validate/validate_pb.js";
import type { MetadataMutable, MetadataUpdateEnum } from "../../common/common_pb.js";
import { file_common_common } from "../../common/common_pb.js";
import type { Action, SubjectMapping } from "../objects_pb.js";
import { file_policy_objects } from "../objects_pb.js";
import { file_policy_predefined_rules } from "../predefined_rules_pb.js";
import type { PageRequest, PageResponse } from "../selectors_pb.js";
import { file_policy_selectors } from "../selectors_pb.js";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file policy/actions/actions.proto.
 */
export const file_policy_actions_actions: GenFile = /*@__PURE__*/
  fileDesc("Chxwb2xpY3kvYWN0aW9ucy9hY3Rpb25zLnByb3RvEg5wb2xpY3kuYWN0aW9ucyJcChBHZXRBY3Rpb25SZXF1ZXN0EhYKAmlkGAEgASgJQgi6SAVyA7ABAUgAEhsKBG5hbWUYAiABKAlCC7pICHIGyLOusQIBSABCEwoKaWRlbnRpZmllchIFukgCCAEiZQoRR2V0QWN0aW9uUmVzcG9uc2USHgoGYWN0aW9uGAEgASgLMg4ucG9saWN5LkFjdGlvbhIwChBzdWJqZWN0X21hcHBpbmdzGAIgAygLMhYucG9saWN5LlN1YmplY3RNYXBwaW5nIj0KEkxpc3RBY3Rpb25zUmVxdWVzdBInCgpwYWdpbmF0aW9uGAogASgLMhMucG9saWN5LlBhZ2VSZXF1ZXN0IpEBChNMaXN0QWN0aW9uc1Jlc3BvbnNlEigKEGFjdGlvbnNfc3RhbmRhcmQYASADKAsyDi5wb2xpY3kuQWN0aW9uEiYKDmFjdGlvbnNfY3VzdG9tGAIgAygLMg4ucG9saWN5LkFjdGlvbhIoCgpwYWdpbmF0aW9uGAogASgLMhQucG9saWN5LlBhZ2VSZXNwb25zZSJbChNDcmVhdGVBY3Rpb25SZXF1ZXN0EhkKBG5hbWUYASABKAlCC7pICHIGwLOusQIBEikKCG1ldGFkYXRhGGQgASgLMhcuY29tbW9uLk1ldGFkYXRhTXV0YWJsZSI2ChRDcmVhdGVBY3Rpb25SZXNwb25zZRIeCgZhY3Rpb24YASABKAsyDi5wb2xpY3kuQWN0aW9uIq8BChNVcGRhdGVBY3Rpb25SZXF1ZXN0EhQKAmlkGAEgASgJQgi6SAVyA7ABARIZCgRuYW1lGAIgASgJQgu6SAhyBsizrrECARIpCghtZXRhZGF0YRhkIAEoCzIXLmNvbW1vbi5NZXRhZGF0YU11dGFibGUSPAoYbWV0YWRhdGFfdXBkYXRlX2JlaGF2aW9yGGUgASgOMhouY29tbW9uLk1ldGFkYXRhVXBkYXRlRW51bSI2ChRVcGRhdGVBY3Rpb25SZXNwb25zZRIeCgZhY3Rpb24YASABKAsyDi5wb2xpY3kuQWN0aW9uIisKE0RlbGV0ZUFjdGlvblJlcXVlc3QSFAoCaWQYASABKAlCCLpIBXIDsAEBIjYKFERlbGV0ZUFjdGlvblJlc3BvbnNlEh4KBmFjdGlvbhgBIAEoCzIOLnBvbGljeS5BY3Rpb24y1AMKDUFjdGlvblNlcnZpY2USUgoJR2V0QWN0aW9uEiAucG9saWN5LmFjdGlvbnMuR2V0QWN0aW9uUmVxdWVzdBohLnBvbGljeS5hY3Rpb25zLkdldEFjdGlvblJlc3BvbnNlIgASWAoLTGlzdEFjdGlvbnMSIi5wb2xpY3kuYWN0aW9ucy5MaXN0QWN0aW9uc1JlcXVlc3QaIy5wb2xpY3kuYWN0aW9ucy5MaXN0QWN0aW9uc1Jlc3BvbnNlIgASWwoMQ3JlYXRlQWN0aW9uEiMucG9saWN5LmFjdGlvbnMuQ3JlYXRlQWN0aW9uUmVxdWVzdBokLnBvbGljeS5hY3Rpb25zLkNyZWF0ZUFjdGlvblJlc3BvbnNlIgASWwoMVXBkYXRlQWN0aW9uEiMucG9saWN5LmFjdGlvbnMuVXBkYXRlQWN0aW9uUmVxdWVzdBokLnBvbGljeS5hY3Rpb25zLlVwZGF0ZUFjdGlvblJlc3BvbnNlIgASWwoMRGVsZXRlQWN0aW9uEiMucG9saWN5LmFjdGlvbnMuRGVsZXRlQWN0aW9uUmVxdWVzdBokLnBvbGljeS5hY3Rpb25zLkRlbGV0ZUFjdGlvblJlc3BvbnNlIgBiBnByb3RvMw", [file_buf_validate_validate, file_common_common, file_policy_objects, file_policy_predefined_rules, file_policy_selectors]);

/**
 * @generated from message policy.actions.GetActionRequest
 */
export type GetActionRequest = Message<"policy.actions.GetActionRequest"> & {
  /**
   * Required
   *
   * @generated from oneof policy.actions.GetActionRequest.identifier
   */
  identifier: {
    /**
     * @generated from field: string id = 1;
     */
    value: string;
    case: "id";
  } | {
    /**
     * @generated from field: string name = 2;
     */
    value: string;
    case: "name";
  } | { case: undefined; value?: undefined };
};

/**
 * Describes the message policy.actions.GetActionRequest.
 * Use `create(GetActionRequestSchema)` to create a new message.
 */
export const GetActionRequestSchema: GenMessage<GetActionRequest> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 0);

/**
 * @generated from message policy.actions.GetActionResponse
 */
export type GetActionResponse = Message<"policy.actions.GetActionResponse"> & {
  /**
   * @generated from field: policy.Action action = 1;
   */
  action?: Action;

  /**
   * Subject Mappings driving entitlement to the action
   *
   * @generated from field: repeated policy.SubjectMapping subject_mappings = 2;
   */
  subjectMappings: SubjectMapping[];
};

/**
 * Describes the message policy.actions.GetActionResponse.
 * Use `create(GetActionResponseSchema)` to create a new message.
 */
export const GetActionResponseSchema: GenMessage<GetActionResponse> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 1);

/**
 * @generated from message policy.actions.ListActionsRequest
 */
export type ListActionsRequest = Message<"policy.actions.ListActionsRequest"> & {
  /**
   * Optional
   *
   * @generated from field: policy.PageRequest pagination = 10;
   */
  pagination?: PageRequest;
};

/**
 * Describes the message policy.actions.ListActionsRequest.
 * Use `create(ListActionsRequestSchema)` to create a new message.
 */
export const ListActionsRequestSchema: GenMessage<ListActionsRequest> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 2);

/**
 * @generated from message policy.actions.ListActionsResponse
 */
export type ListActionsResponse = Message<"policy.actions.ListActionsResponse"> & {
  /**
   * @generated from field: repeated policy.Action actions_standard = 1;
   */
  actionsStandard: Action[];

  /**
   * @generated from field: repeated policy.Action actions_custom = 2;
   */
  actionsCustom: Action[];

  /**
   * @generated from field: policy.PageResponse pagination = 10;
   */
  pagination?: PageResponse;
};

/**
 * Describes the message policy.actions.ListActionsResponse.
 * Use `create(ListActionsResponseSchema)` to create a new message.
 */
export const ListActionsResponseSchema: GenMessage<ListActionsResponse> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 3);

/**
 * Create a new Custom action name with optional metadata.
 * Creation of Standard actions is not supported.
 *
 * @generated from message policy.actions.CreateActionRequest
 */
export type CreateActionRequest = Message<"policy.actions.CreateActionRequest"> & {
  /**
   * Required
   *
   * @generated from field: string name = 1;
   */
  name: string;

  /**
   * Optional
   *
   * @generated from field: common.MetadataMutable metadata = 100;
   */
  metadata?: MetadataMutable;
};

/**
 * Describes the message policy.actions.CreateActionRequest.
 * Use `create(CreateActionRequestSchema)` to create a new message.
 */
export const CreateActionRequestSchema: GenMessage<CreateActionRequest> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 4);

/**
 * @generated from message policy.actions.CreateActionResponse
 */
export type CreateActionResponse = Message<"policy.actions.CreateActionResponse"> & {
  /**
   * @generated from field: policy.Action action = 1;
   */
  action?: Action;
};

/**
 * Describes the message policy.actions.CreateActionResponse.
 * Use `create(CreateActionResponseSchema)` to create a new message.
 */
export const CreateActionResponseSchema: GenMessage<CreateActionResponse> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 5);

/**
 * Metadata may be updated for either Custom or Standard actions.
 * Names may only be updated for Custom actions.
 *
 * @generated from message policy.actions.UpdateActionRequest
 */
export type UpdateActionRequest = Message<"policy.actions.UpdateActionRequest"> & {
  /**
   * Required
   *
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * Optional
   * Custom actions only: replaces the existing action name
   *
   * @generated from field: string name = 2;
   */
  name: string;

  /**
   * Common metadata
   *
   * @generated from field: common.MetadataMutable metadata = 100;
   */
  metadata?: MetadataMutable;

  /**
   * @generated from field: common.MetadataUpdateEnum metadata_update_behavior = 101;
   */
  metadataUpdateBehavior: MetadataUpdateEnum;
};

/**
 * Describes the message policy.actions.UpdateActionRequest.
 * Use `create(UpdateActionRequestSchema)` to create a new message.
 */
export const UpdateActionRequestSchema: GenMessage<UpdateActionRequest> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 6);

/**
 * @generated from message policy.actions.UpdateActionResponse
 */
export type UpdateActionResponse = Message<"policy.actions.UpdateActionResponse"> & {
  /**
   * @generated from field: policy.Action action = 1;
   */
  action?: Action;
};

/**
 * Describes the message policy.actions.UpdateActionResponse.
 * Use `create(UpdateActionResponseSchema)` to create a new message.
 */
export const UpdateActionResponseSchema: GenMessage<UpdateActionResponse> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 7);

/**
 * Custom only: deletion of Standard actions is not supported.
 *
 * @generated from message policy.actions.DeleteActionRequest
 */
export type DeleteActionRequest = Message<"policy.actions.DeleteActionRequest"> & {
  /**
   * Required
   *
   * @generated from field: string id = 1;
   */
  id: string;
};

/**
 * Describes the message policy.actions.DeleteActionRequest.
 * Use `create(DeleteActionRequestSchema)` to create a new message.
 */
export const DeleteActionRequestSchema: GenMessage<DeleteActionRequest> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 8);

/**
 * @generated from message policy.actions.DeleteActionResponse
 */
export type DeleteActionResponse = Message<"policy.actions.DeleteActionResponse"> & {
  /**
   * @generated from field: policy.Action action = 1;
   */
  action?: Action;
};

/**
 * Describes the message policy.actions.DeleteActionResponse.
 * Use `create(DeleteActionResponseSchema)` to create a new message.
 */
export const DeleteActionResponseSchema: GenMessage<DeleteActionResponse> = /*@__PURE__*/
  messageDesc(file_policy_actions_actions, 9);

/**
 * @generated from service policy.actions.ActionService
 */
export const ActionService: GenService<{
  /**
   * @generated from rpc policy.actions.ActionService.GetAction
   */
  getAction: {
    methodKind: "unary";
    input: typeof GetActionRequestSchema;
    output: typeof GetActionResponseSchema;
  },
  /**
   * @generated from rpc policy.actions.ActionService.ListActions
   */
  listActions: {
    methodKind: "unary";
    input: typeof ListActionsRequestSchema;
    output: typeof ListActionsResponseSchema;
  },
  /**
   * @generated from rpc policy.actions.ActionService.CreateAction
   */
  createAction: {
    methodKind: "unary";
    input: typeof CreateActionRequestSchema;
    output: typeof CreateActionResponseSchema;
  },
  /**
   * @generated from rpc policy.actions.ActionService.UpdateAction
   */
  updateAction: {
    methodKind: "unary";
    input: typeof UpdateActionRequestSchema;
    output: typeof UpdateActionResponseSchema;
  },
  /**
   * @generated from rpc policy.actions.ActionService.DeleteAction
   */
  deleteAction: {
    methodKind: "unary";
    input: typeof DeleteActionRequestSchema;
    output: typeof DeleteActionResponseSchema;
  },
}> = /*@__PURE__*/
  serviceDesc(file_policy_actions_actions, 0);

