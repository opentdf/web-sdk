import { expect } from 'chai';
import {
  ActiveStateEnum,
  AttributeRuleTypeEnum,
  ConditionBooleanTypeEnum,
  SubjectMappingOperatorEnum,
} from '../../../src/index.js';

describe('Policy enum re-exports', () => {
  it('exports SubjectMappingOperatorEnum with expected values', () => {
    expect(SubjectMappingOperatorEnum.IN).to.equal(1);
    expect(SubjectMappingOperatorEnum.NOT_IN).to.equal(2);
    expect(SubjectMappingOperatorEnum.IN_CONTAINS).to.equal(3);
  });

  it('exports ConditionBooleanTypeEnum with expected values', () => {
    expect(ConditionBooleanTypeEnum.AND).to.equal(1);
    expect(ConditionBooleanTypeEnum.OR).to.equal(2);
  });

  it('exports AttributeRuleTypeEnum with expected values', () => {
    expect(AttributeRuleTypeEnum.ALL_OF).to.equal(1);
    expect(AttributeRuleTypeEnum.ANY_OF).to.equal(2);
    expect(AttributeRuleTypeEnum.HIERARCHY).to.equal(3);
  });

  it('exports ActiveStateEnum with expected values', () => {
    expect(ActiveStateEnum.ACTIVE).to.equal(1);
    expect(ActiveStateEnum.INACTIVE).to.equal(2);
    expect(ActiveStateEnum.ANY).to.equal(3);
  });
});
