// @generated by protoc-gen-connect-es v1.4.0 with parameter "target=ts"
// @generated from file policy/subjectmapping/subject_mapping.proto (package policy.subjectmapping, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import {
  CreateSubjectConditionSetRequest,
  CreateSubjectConditionSetResponse,
  CreateSubjectMappingRequest,
  CreateSubjectMappingResponse,
  DeleteSubjectConditionSetRequest,
  DeleteSubjectConditionSetResponse,
  DeleteSubjectMappingRequest,
  DeleteSubjectMappingResponse,
  GetSubjectConditionSetRequest,
  GetSubjectConditionSetResponse,
  GetSubjectMappingRequest,
  GetSubjectMappingResponse,
  ListSubjectConditionSetsRequest,
  ListSubjectConditionSetsResponse,
  ListSubjectMappingsRequest,
  ListSubjectMappingsResponse,
  MatchSubjectMappingsRequest,
  MatchSubjectMappingsResponse,
  UpdateSubjectConditionSetRequest,
  UpdateSubjectConditionSetResponse,
  UpdateSubjectMappingRequest,
  UpdateSubjectMappingResponse,
} from './subject_mapping_pb.js';
import { MethodKind } from '@bufbuild/protobuf';

/**
 * @generated from service policy.subjectmapping.SubjectMappingService
 */
export const SubjectMappingService = {
  typeName: 'policy.subjectmapping.SubjectMappingService',
  methods: {
    /**
     * Find matching Subject Mappings for a given Subject
     *
     * @generated from rpc policy.subjectmapping.SubjectMappingService.MatchSubjectMappings
     */
    matchSubjectMappings: {
      name: 'MatchSubjectMappings',
      I: MatchSubjectMappingsRequest,
      O: MatchSubjectMappingsResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.ListSubjectMappings
     */
    listSubjectMappings: {
      name: 'ListSubjectMappings',
      I: ListSubjectMappingsRequest,
      O: ListSubjectMappingsResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.GetSubjectMapping
     */
    getSubjectMapping: {
      name: 'GetSubjectMapping',
      I: GetSubjectMappingRequest,
      O: GetSubjectMappingResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.CreateSubjectMapping
     */
    createSubjectMapping: {
      name: 'CreateSubjectMapping',
      I: CreateSubjectMappingRequest,
      O: CreateSubjectMappingResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.UpdateSubjectMapping
     */
    updateSubjectMapping: {
      name: 'UpdateSubjectMapping',
      I: UpdateSubjectMappingRequest,
      O: UpdateSubjectMappingResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.DeleteSubjectMapping
     */
    deleteSubjectMapping: {
      name: 'DeleteSubjectMapping',
      I: DeleteSubjectMappingRequest,
      O: DeleteSubjectMappingResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.ListSubjectConditionSets
     */
    listSubjectConditionSets: {
      name: 'ListSubjectConditionSets',
      I: ListSubjectConditionSetsRequest,
      O: ListSubjectConditionSetsResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.GetSubjectConditionSet
     */
    getSubjectConditionSet: {
      name: 'GetSubjectConditionSet',
      I: GetSubjectConditionSetRequest,
      O: GetSubjectConditionSetResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.CreateSubjectConditionSet
     */
    createSubjectConditionSet: {
      name: 'CreateSubjectConditionSet',
      I: CreateSubjectConditionSetRequest,
      O: CreateSubjectConditionSetResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.UpdateSubjectConditionSet
     */
    updateSubjectConditionSet: {
      name: 'UpdateSubjectConditionSet',
      I: UpdateSubjectConditionSetRequest,
      O: UpdateSubjectConditionSetResponse,
      kind: MethodKind.Unary,
    },
    /**
     * @generated from rpc policy.subjectmapping.SubjectMappingService.DeleteSubjectConditionSet
     */
    deleteSubjectConditionSet: {
      name: 'DeleteSubjectConditionSet',
      I: DeleteSubjectConditionSetRequest,
      O: DeleteSubjectConditionSetResponse,
      kind: MethodKind.Unary,
    },
  },
} as const;
