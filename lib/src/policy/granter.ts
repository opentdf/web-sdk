import { ConfigurationError } from '../errors.js';
import { Attribute, AttributeRuleType, KeyAccessServer, Value } from './attributes.js';

type KeySplitStep = {
  kas: KeyAccessServer;
  kid?: string;
  sid: string;
};

type AttributeClause = {
  def: Attribute;
  values: string[];
};

type AndClause = {
  op: 'allOf';
  granters: KeyAccessServer[];
};

type HeirarchyClause = {
  op: 'hierarchy';
  granters: KeyAccessServer[];
};

type OrClause = {
  op: 'anyOf';
  granters: KeyAccessServer[];
};

type BooleanClause = AndClause | OrClause | HeirarchyClause;

type BooleanOperator = BooleanClause['op'];

type ComplexBooleanClause = {
  op: BooleanOperator;
  children: BooleanClause[];
};

export function booleanOperatorFor(rule?: AttributeRuleType): BooleanOperator {
  switch (rule) {
    case AttributeRuleType.UNSPECIFIED:
    case AttributeRuleType.ALL_OF:
      return 'allOf';
    case AttributeRuleType.ANY_OF:
      return 'anyOf';
    case AttributeRuleType.HIERARCHY:
      return 'hierarchy';
    default:
      return 'allOf';
  }
}

type ValueFQN = string;
export function plan(dataAttrs: Value[]): KeySplitStep[] {
  // KASes by value
  const granters: Record<ValueFQN, Set<KeyAccessServer>> = Object.create(null);
  // Values grouped by normalized attribute prefix
  const allClauses: Record<string, AttributeClause> = Object.create(null);

  const addGrants = (valueFQN: string, gs?: KeyAccessServer[]): boolean => {
    if (!(valueFQN in granters)) {
      granters[valueFQN] = new Set();
    }
    if (!gs?.length) {
      return false;
    }
    for (const g of gs) {
      granters[valueFQN].add(g);
    }
    return true;
  };

  for (const v of dataAttrs) {
    const { attribute, fqn } = v;
    if (!attribute) {
      throw new ConfigurationError(`attribute not defined for [${fqn}]`);
    }
    const valFqn = fqn.toLowerCase();
    const attrFqn = attribute.fqn.toLowerCase();
    if (!(attrFqn in allClauses)) {
      allClauses[attrFqn] = {
        def: attribute,
        values: [],
      };
    }
    allClauses[attrFqn].values.push(valFqn);
    if (!addGrants(valFqn, v.grants)) {
      if (!addGrants(valFqn, attribute.grants)) {
        addGrants(valFqn, attribute.namespace?.grants);
      }
    }
  }
  const kcs: ComplexBooleanClause[] = [];
  for (const attrClause of Object.values(allClauses)) {
    // Create wrapper clauses for each value, [(ANY_OF Value-1), (ANY_OF Value-2)]
    const individualValueClauses: BooleanClause[] = [];
    for (const attrValue of attrClause.values) {
      const grantersForAttr = granters[attrValue] || new Set();
      if (grantersForAttr.size) {
        individualValueClauses.push({
          op: 'anyOf',
          granters: Array.from(grantersForAttr.values()),
        });
      }
    }
    // Use proper boolean operation with wrapped values.
    const op = booleanOperatorFor(attrClause.def?.rule);
    kcs.push({
      op,
      children: individualValueClauses,
    });
  }
  return simplify(kcs);
}

function simplify(clauses: ComplexBooleanClause[]): KeySplitStep[] {
  const conjunction: Record<string, KeyAccessServer[]> = {};
  function keyFor(granters: KeyAccessServer[]): string {
    const keyParts = granters
      .sort((a, b) => {
        return a.id.localeCompare(b.id);
      })
      .map((granter) => {
        if (!granter.publicKey) {
          return granter.id;
        }
        const publicKey = granter.publicKey.publicKey;
        switch (publicKey.case) {
          case 'remote':
            return publicKey.value;

          case 'cached':
            return publicKey.value.keys
              .map((key) => key.kid)
              .sort()
              .join('');

          default:
            throw new Error(`Unknown public key type: ${publicKey.case}`);
        }
      });
    return keyParts.join('');
  }
  for (const { op, children } of clauses) {
    if (!children) {
      continue;
    }
    if (op === 'anyOf') {
      const granters: KeyAccessServer[] = [];
      for (const bc of children) {
        if (bc.op != 'anyOf') {
          throw new Error('internal: autoconfigure inversion in disjunction');
        }
        if (!bc.granters.length) {
          continue;
        }
        granters.push(...bc.granters);
      }
      if (!granters.length) {
        continue;
      }
      const k = keyFor(granters);
      conjunction[k] = granters;
    } else {
      for (const bc of children) {
        if (bc.op != 'anyOf') {
          throw new Error('internal: autoconfigure inversion in conjunction');
        }
        if (!bc.granters.length) {
          continue;
        }
        const k = keyFor(bc.granters);
        conjunction[k] = bc.granters;
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
      if (kas.publicKey && kas.publicKey.publicKey.case === 'cached') {
        kas.publicKey.publicKey.value.keys.forEach((key) => {
          t.push({ sid, kas: kas, kid: key.kid });
        });
      } else {
        t.push({ sid, kas: kas });
      }
    }
  }
  return t;
}
