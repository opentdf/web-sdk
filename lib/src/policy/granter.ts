import { Attribute, AttributeRuleType, KeyAccessServer, Value } from './attributes.js';

export type KeySplitStep = {
  kas: KeyAccessServer;
  sid?: string;
};

type AttributeClause = {
  def: Attribute;
  values: string[];
};

type AndClause = {
  op: 'allOf';
  kases: string[];
};

type HeirarchyClause = {
  op: 'hierarchy';
  kases: string[];
};

type OrClause = {
  op: 'anyOf';
  kases: string[];
};

type BooleanClause = AndClause | OrClause | HeirarchyClause;

type BooleanOperator = BooleanClause['op'];

type ComplexBooleanClause = {
  op: BooleanOperator;
  children: BooleanClause[];
};

export function booleanOperatorFor(rule?: AttributeRuleType): BooleanOperator {
  if (!rule) {
    return 'allOf';
  }
  switch (rule) {
    case 'ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED':
    case 'ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF':
      return 'allOf';
    case 'ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF':
      return 'anyOf';
    case 'ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY':
      return 'hierarchy';
  }
}

export function plan(dataAttrs: Value[]): KeySplitStep[] {
  // KASes by value
  const grants: Record<string, Set<string>> = {};
  // KAS detail by KAS url
  const kasInfo: Record<string, KeyAccessServer> = {};
  // Attribute definitions in use
  const prefixes: Set<string> = new Set();
  // Values grouped by normalized attribute prefix
  const allClauses: Record<string, AttributeClause> = {};
  // Values by normalized FQN
  const allValues: Record<string, Value> = {};

  const addGrants = (val: string, gs?: KeyAccessServer[]): boolean => {
    if (!gs?.length) {
      if (!(val in grants)) {
        grants[val] = new Set();
      }
      return false;
    }
    for (const g of gs) {
      if (val in grants) {
        grants[val].add(g.uri);
      } else {
        grants[val] = new Set([g.uri]);
      }
      kasInfo[g.uri] = g;
    }
    return true;
  };

  for (const v of dataAttrs) {
    const { attribute, fqn } = v;
    if (!attribute) {
      throw new Error(`attribute not defined for [${fqn}]`);
    }
    const valFqn = fqn.toLowerCase();
    const attrFqn = attribute.fqn.toLowerCase();
    if (!prefixes.has(attrFqn)) {
      prefixes.add(attrFqn);
      allClauses[attrFqn] = {
        def: attribute,
        values: [],
      };
    }
    allClauses[attrFqn].values.push(valFqn);
    allValues[valFqn] = v;
    if (!addGrants(valFqn, v.grants)) {
      if (!addGrants(valFqn, attribute.grants)) {
        addGrants(valFqn, attribute.namespace?.grants);
      }
    }
  }
  const kcs: ComplexBooleanClause[] = [];
  for (const attrClause of Object.values(allClauses)) {
    const ccv: BooleanClause[] = [];
    for (const term of attrClause.values) {
      const grantsForTerm = Array.from(grants[term] || []);
      if (grantsForTerm?.length) {
        ccv.push({
          op: 'anyOf',
          kases: grantsForTerm,
        });
      }
    }
    const op = booleanOperatorFor(attrClause.def.rule);
    kcs.push({
      op,
      children: ccv,
    });
  }
  return simplify(kcs, kasInfo);
}

function simplify(
  clauses: ComplexBooleanClause[],
  kasInfo: Record<string, KeyAccessServer>
): KeySplitStep[] {
  const conjunction: Record<string, string[]> = {};
  function keyFor(kases: string[]): string {
    const k = Array.from(new Set([kases])).sort();
    return k.join('|');
  }
  for (const { op, children } of clauses) {
    if (!children) {
      continue;
    }
    if (op === 'anyOf') {
      const anyKids = [];
      for (const bc of children) {
        if (bc.op != 'anyOf') {
          throw new Error('inversion');
        }
        if (!bc.kases?.length) {
          continue;
        }
        anyKids.push(...bc.kases);
      }
      if (!anyKids?.length) {
        continue;
      }
      const k = keyFor(anyKids);
      conjunction[k] = anyKids;
    } else {
      for (const bc of children) {
        if (bc.op != 'anyOf') {
          throw new Error('inversion');
        }
        if (!bc.kases?.length) {
          continue;
        }
        const k = keyFor(bc.kases);
        conjunction[k] = bc.kases;
      }
    }
  }
  const t: KeySplitStep[] = [];
  let i = 0;
  for (const k of Object.keys(conjunction).sort()) {
    if (!conjunction[k]) {
      continue;
    }
    i += 1;
    const sid = '' + i;
    for (const kas of conjunction[k]) {
      t.push({ sid, kas: kasInfo[kas] });
    }
  }
  return t;
}
