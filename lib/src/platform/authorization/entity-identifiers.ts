import { create } from '@bufbuild/protobuf';
import { BoolValueSchema } from '@bufbuild/protobuf/wkt';
import {
  type EntityIdentifier,
  EntityIdentifierSchema,
} from './v2/authorization_pb.js';
import {
  type Entity,
  Entity_Category,
  EntityChainSchema,
  EntitySchema,
  TokenSchema,
} from '../entity/entity_pb.js';

/**
 * Convenience constructors for {@link EntityIdentifier}, mirroring the Go SDK
 * helpers (`ForEmail`, `ForClientID`, etc.).
 *
 * Each function builds a complete `EntityIdentifier` so callers avoid deeply
 * nested object literals.
 *
 * @example
 * ```ts
 * // Before
 * const eid = create(EntityIdentifierSchema, {
 *   identifier: {
 *     case: 'entityChain',
 *     value: create(EntityChainSchema, {
 *       entities: [create(EntitySchema, {
 *         entityType: { case: 'emailAddress', value: 'jen@example.com' },
 *         category: Entity_Category.SUBJECT,
 *       })],
 *     }),
 *   },
 * });
 *
 * // After
 * const eid = forEmail('jen@example.com');
 * ```
 */

/** Returns an EntityIdentifier for a subject identified by email address. */
export function forEmail(email: string): EntityIdentifier {
  return fromEntity(
    create(EntitySchema, {
      entityType: { case: 'emailAddress', value: email },
      category: Entity_Category.SUBJECT,
    })
  );
}

/** Returns an EntityIdentifier for a subject identified by client ID. */
export function forClientId(clientId: string): EntityIdentifier {
  return fromEntity(
    create(EntitySchema, {
      entityType: { case: 'clientId', value: clientId },
      category: Entity_Category.SUBJECT,
    })
  );
}

/** Returns an EntityIdentifier for a subject identified by username. */
export function forUserName(userName: string): EntityIdentifier {
  return fromEntity(
    create(EntitySchema, {
      entityType: { case: 'userName', value: userName },
      category: Entity_Category.SUBJECT,
    })
  );
}

/** Returns an EntityIdentifier that resolves the entity from the given JWT. */
export function forToken(jwt: string): EntityIdentifier {
  return create(EntityIdentifierSchema, {
    identifier: {
      case: 'token',
      value: create(TokenSchema, { jwt }),
    },
  });
}

/**
 * Returns an EntityIdentifier that instructs the authorization service to
 * derive the entity from the request's Authorization header token.
 */
export function withRequestToken(): EntityIdentifier {
  return create(EntityIdentifierSchema, {
    identifier: {
      case: 'withRequestToken',
      value: create(BoolValueSchema, { value: true }),
    },
  });
}

function fromEntity(entity: Entity): EntityIdentifier {
  return create(EntityIdentifierSchema, {
    identifier: {
      case: 'entityChain',
      value: create(EntityChainSchema, { entities: [entity] }),
    },
  });
}
