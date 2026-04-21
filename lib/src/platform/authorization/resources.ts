import { create } from '@bufbuild/protobuf';
import {
  type Resource,
  ResourceSchema,
  Resource_AttributeValuesSchema,
} from './v2/authorization_pb.js';

/**
 * Convenience constructors for {@link Resource}, mirroring the Go SDK helpers
 * (`ForAttributeValues`, `ForRegisteredResourceValueFqn`).
 *
 * Each function builds a complete `Resource` so callers avoid deeply nested
 * object literals.
 *
 * @example
 * ```ts
 * // Before
 * const resource = create(ResourceSchema, {
 *   resource: {
 *     case: 'attributeValues',
 *     value: create(Resource_AttributeValuesSchema, {
 *       fqns: ['https://example.com/attr/department/value/finance'],
 *     }),
 *   },
 * });
 *
 * // After
 * import { Resources } from '@opentdf/sdk';
 * const resource = Resources.forAttributeValues('https://example.com/attr/department/value/finance');
 * ```
 */

/**
 * Returns a Resource containing the given attribute value FQNs.
 * This is the most common Resource variant, used when authorizing against
 * attribute values attached to data (e.g. those on a TDF).
 */
export function forAttributeValues(...fqns: string[]): Resource {
  return create(ResourceSchema, {
    resource: {
      case: 'attributeValues',
      value: create(Resource_AttributeValuesSchema, { fqns }),
    },
  });
}

/**
 * Returns a Resource that references a single registered resource value
 * by its fully qualified name, as stored in platform policy.
 */
export function forRegisteredResourceValueFqn(fqn: string): Resource {
  return create(ResourceSchema, {
    resource: {
      case: 'registeredResourceValueFqn',
      value: fqn,
    },
  });
}
