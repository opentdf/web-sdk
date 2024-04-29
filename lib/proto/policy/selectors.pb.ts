/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/
export type AttributeNamespaceSelectorAttributeSelectorValueSelector = {
  withKeyAccessGrants?: boolean
  withSubjectMaps?: boolean
  withResourceMaps?: boolean
}

export type AttributeNamespaceSelectorAttributeSelector = {
  withKeyAccessGrants?: boolean
  withValues?: AttributeNamespaceSelectorAttributeSelectorValueSelector
}

export type AttributeNamespaceSelector = {
  withAttributes?: AttributeNamespaceSelectorAttributeSelector
}

export type AttributeDefinitionSelectorNamespaceSelector = {
}

export type AttributeDefinitionSelectorValueSelector = {
  withKeyAccessGrants?: boolean
  withSubjectMaps?: boolean
  withResourceMaps?: boolean
}

export type AttributeDefinitionSelector = {
  withKeyAccessGrants?: boolean
  withNamespace?: AttributeDefinitionSelectorNamespaceSelector
  withValues?: AttributeDefinitionSelectorValueSelector
}

export type AttributeValueSelectorAttributeSelectorNamespaceSelector = {
}

export type AttributeValueSelectorAttributeSelector = {
  withKeyAccessGrants?: boolean
  withNamespace?: AttributeValueSelectorAttributeSelectorNamespaceSelector
}

export type AttributeValueSelector = {
  withKeyAccessGrants?: boolean
  withSubjectMaps?: boolean
  withResourceMaps?: boolean
  withAttribute?: AttributeValueSelectorAttributeSelector
}