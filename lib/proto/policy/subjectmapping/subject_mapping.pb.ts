/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as CommonCommon from "../../common/common.pb"
import * as fm from "../../fetch.pb"
import * as PolicyObjects from "../objects.pb"
export type MatchSubjectMappingsRequest = {
  subjectProperties?: PolicyObjects.SubjectProperty[]
}

export type MatchSubjectMappingsResponse = {
  subjectMappings?: PolicyObjects.SubjectMapping[]
}

export type GetSubjectMappingRequest = {
  id?: string
}

export type GetSubjectMappingResponse = {
  subjectMapping?: PolicyObjects.SubjectMapping
}

export type ListSubjectMappingsRequest = {
}

export type ListSubjectMappingsResponse = {
  subjectMappings?: PolicyObjects.SubjectMapping[]
}

export type CreateSubjectMappingRequest = {
  attributeValueId?: string
  actions?: PolicyObjects.Action[]
  existingSubjectConditionSetId?: string
  newSubjectConditionSet?: SubjectConditionSetCreate
  metadata?: CommonCommon.MetadataMutable
}

export type CreateSubjectMappingResponse = {
  subjectMapping?: PolicyObjects.SubjectMapping
}

export type UpdateSubjectMappingRequest = {
  id?: string
  subjectConditionSetId?: string
  actions?: PolicyObjects.Action[]
  metadata?: CommonCommon.MetadataMutable
  metadataUpdateBehavior?: CommonCommon.MetadataUpdateEnum
}

export type UpdateSubjectMappingResponse = {
  subjectMapping?: PolicyObjects.SubjectMapping
}

export type DeleteSubjectMappingRequest = {
  id?: string
}

export type DeleteSubjectMappingResponse = {
  subjectMapping?: PolicyObjects.SubjectMapping
}

export type GetSubjectConditionSetRequest = {
  id?: string
}

export type GetSubjectConditionSetResponse = {
  subjectConditionSet?: PolicyObjects.SubjectConditionSet
  associatedSubjectMappings?: PolicyObjects.SubjectMapping[]
}

export type ListSubjectConditionSetsRequest = {
}

export type ListSubjectConditionSetsResponse = {
  subjectConditionSets?: PolicyObjects.SubjectConditionSet[]
}

export type SubjectConditionSetCreate = {
  subjectSets?: PolicyObjects.SubjectSet[]
  metadata?: CommonCommon.MetadataMutable
}

export type CreateSubjectConditionSetRequest = {
  subjectConditionSet?: SubjectConditionSetCreate
}

export type CreateSubjectConditionSetResponse = {
  subjectConditionSet?: PolicyObjects.SubjectConditionSet
}

export type UpdateSubjectConditionSetRequest = {
  id?: string
  subjectSets?: PolicyObjects.SubjectSet[]
  metadata?: CommonCommon.MetadataMutable
  metadataUpdateBehavior?: CommonCommon.MetadataUpdateEnum
}

export type UpdateSubjectConditionSetResponse = {
  subjectConditionSet?: PolicyObjects.SubjectConditionSet
}

export type DeleteSubjectConditionSetRequest = {
  id?: string
}

export type DeleteSubjectConditionSetResponse = {
  subjectConditionSet?: PolicyObjects.SubjectConditionSet
}

export class SubjectMappingService {
  static MatchSubjectMappings(req: MatchSubjectMappingsRequest, initReq?: fm.InitReq): Promise<MatchSubjectMappingsResponse> {
    return fm.fetchReq<MatchSubjectMappingsRequest, MatchSubjectMappingsResponse>(`/subject-mappings/match`, {...initReq, method: "POST", body: JSON.stringify(req["subject_properties"], fm.replacer)})
  }
  static ListSubjectMappings(req: ListSubjectMappingsRequest, initReq?: fm.InitReq): Promise<ListSubjectMappingsResponse> {
    return fm.fetchReq<ListSubjectMappingsRequest, ListSubjectMappingsResponse>(`/subject-mappings?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetSubjectMapping(req: GetSubjectMappingRequest, initReq?: fm.InitReq): Promise<GetSubjectMappingResponse> {
    return fm.fetchReq<GetSubjectMappingRequest, GetSubjectMappingResponse>(`/subject-mappings/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateSubjectMapping(req: CreateSubjectMappingRequest, initReq?: fm.InitReq): Promise<CreateSubjectMappingResponse> {
    return fm.fetchReq<CreateSubjectMappingRequest, CreateSubjectMappingResponse>(`/subject-mappings`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateSubjectMapping(req: UpdateSubjectMappingRequest, initReq?: fm.InitReq): Promise<UpdateSubjectMappingResponse> {
    return fm.fetchReq<UpdateSubjectMappingRequest, UpdateSubjectMappingResponse>(`/subject-mappings/${req["id"]}`, {...initReq, method: "PATCH", body: JSON.stringify(req, fm.replacer)})
  }
  static DeleteSubjectMapping(req: DeleteSubjectMappingRequest, initReq?: fm.InitReq): Promise<DeleteSubjectMappingResponse> {
    return fm.fetchReq<DeleteSubjectMappingRequest, DeleteSubjectMappingResponse>(`/subject-mappings/${req["id"]}`, {...initReq, method: "DELETE"})
  }
  static ListSubjectConditionSets(req: ListSubjectConditionSetsRequest, initReq?: fm.InitReq): Promise<ListSubjectConditionSetsResponse> {
    return fm.fetchReq<ListSubjectConditionSetsRequest, ListSubjectConditionSetsResponse>(`/subject-condition-sets?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetSubjectConditionSet(req: GetSubjectConditionSetRequest, initReq?: fm.InitReq): Promise<GetSubjectConditionSetResponse> {
    return fm.fetchReq<GetSubjectConditionSetRequest, GetSubjectConditionSetResponse>(`/subject-condition-sets/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateSubjectConditionSet(req: CreateSubjectConditionSetRequest, initReq?: fm.InitReq): Promise<CreateSubjectConditionSetResponse> {
    return fm.fetchReq<CreateSubjectConditionSetRequest, CreateSubjectConditionSetResponse>(`/subject-condition-sets`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateSubjectConditionSet(req: UpdateSubjectConditionSetRequest, initReq?: fm.InitReq): Promise<UpdateSubjectConditionSetResponse> {
    return fm.fetchReq<UpdateSubjectConditionSetRequest, UpdateSubjectConditionSetResponse>(`/subject-condition-sets/${req["id"]}`, {...initReq, method: "PATCH", body: JSON.stringify(req, fm.replacer)})
  }
  static DeleteSubjectConditionSet(req: DeleteSubjectConditionSetRequest, initReq?: fm.InitReq): Promise<DeleteSubjectConditionSetResponse> {
    return fm.fetchReq<DeleteSubjectConditionSetRequest, DeleteSubjectConditionSetResponse>(`/subject-condition-sets/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}