import { expect } from 'chai';
import {
  forEmail,
  forClientId,
  forUserName,
  forToken,
  withRequestToken,
} from '../../../src/index.js';
import { Entity_Category } from '../../../src/platform/entity/entity_pb.js';
import type { EntityChain, Token } from '../../../src/platform/entity/entity_pb.js';
import type { BoolValue } from '@bufbuild/protobuf/wkt';

describe('EntityIdentifier helpers', () => {
  describe('forEmail()', () => {
    for (const email of ['user@example.com', '']) {
      it(`builds an entityChain with emailAddress="${email}"`, () => {
        const eid = forEmail(email);
        expect(eid.identifier.case).to.equal('entityChain');
        const chain = eid.identifier.value as EntityChain;
        expect(chain.entities).to.have.lengthOf(1);
        const entity = chain.entities[0];
        expect(entity.entityType.case).to.equal('emailAddress');
        expect(entity.entityType.value).to.equal(email);
        expect(entity.category).to.equal(Entity_Category.SUBJECT);
      });
    }
  });

  describe('forClientId()', () => {
    for (const clientId of ['my-client', '']) {
      it(`builds an entityChain with clientId="${clientId}"`, () => {
        const eid = forClientId(clientId);
        expect(eid.identifier.case).to.equal('entityChain');
        const chain = eid.identifier.value as EntityChain;
        expect(chain.entities).to.have.lengthOf(1);
        const entity = chain.entities[0];
        expect(entity.entityType.case).to.equal('clientId');
        expect(entity.entityType.value).to.equal(clientId);
        expect(entity.category).to.equal(Entity_Category.SUBJECT);
      });
    }
  });

  describe('forUserName()', () => {
    for (const userName of ['alice', '']) {
      it(`builds an entityChain with userName="${userName}"`, () => {
        const eid = forUserName(userName);
        expect(eid.identifier.case).to.equal('entityChain');
        const chain = eid.identifier.value as EntityChain;
        expect(chain.entities).to.have.lengthOf(1);
        const entity = chain.entities[0];
        expect(entity.entityType.case).to.equal('userName');
        expect(entity.entityType.value).to.equal(userName);
        expect(entity.category).to.equal(Entity_Category.SUBJECT);
      });
    }
  });

  describe('forToken()', () => {
    for (const jwt of ['eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test', '']) {
      it(`builds a token identifier with jwt="${jwt.slice(0, 20)}..."`, () => {
        const eid = forToken(jwt);
        expect(eid.identifier.case).to.equal('token');
        expect((eid.identifier.value as Token).jwt).to.equal(jwt);
      });
    }
  });

  describe('withRequestToken()', () => {
    it('builds a withRequestToken identifier set to true', () => {
      const eid = withRequestToken();
      expect(eid.identifier.case).to.equal('withRequestToken');
      expect((eid.identifier.value as BoolValue).value).to.equal(true);
    });
  });
});
