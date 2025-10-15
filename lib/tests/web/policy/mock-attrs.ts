import {
  Attribute,
  AttributeRuleType,
  KeyAccessServer,
  Namespace,
  Value,
} from '../../../src/policy/attributes.js';
import { kasECCert, kasPublicKey } from '../../mocks/pems.js';
import { KasPublicKeyAlgEnum, SourceType } from '../../../src/platform/policy/objects_pb.js';

export const kasAu = 'https://kas.au/';
export const kasCa = 'https://kas.ca/';
export const kasUk = 'https://kas.uk/';
export const kasNz = 'https://kas.nz/';
export const kasUs = 'https://kas.us/';
export const kasUsHCS = 'https://hcs.kas.us/';
export const kasUsSA = 'https://si.kas.us/';
export const authority = 'https://virtru.com/';
export const otherAuth = 'https://other.com/';
export const specifiedKas = 'https://attr.kas.com/';
export const evenMoreSpecificKas = 'https://value.kas.com/';
export const lessSpecificKas = 'https://namespace.kas.com/';

export const nsStandard = 'https://standard.ns';

export const attrCLS = `${nsStandard}/attr/Classification`;
export const attrN2K = `${nsStandard}/attr/Need%20to%20Know`;
export const attrREL = `${nsStandard}/attr/Releasable%20To`;

export const valClassA = `${attrCLS}/value/Allowed`;
export const valClassS = `${attrCLS}/value/Secret`;
export const valClassTS = `${attrCLS}/value/Top%20Secret`;

export const valN2KHCS = `${attrN2K}/value/HCS`;
export const valN2KINT = `${attrN2K}/value/INT`;
export const valN2KSI = `${attrN2K}/value/SI`;

export const valRelAus = `${attrREL}/value/AUS`;
export const valRelCan = `${attrREL}/value/CAN`;
export const valRelGbr = `${attrREL}/value/GBR`;
export const valRelNzl = `${attrREL}/value/NZL`;
export const valRelUsa = `${attrREL}/value/USA`;
export const valRelFvey = `${attrREL}/value/FVEY`;

// For testing grant specificity
export const nsGranted = 'https://granted.ns';
export const nsUngranted = 'https://ungranted.ns';
export const attrGG = `${nsGranted}/attr/granted`;
export const attrGU = `${nsGranted}/attr/ungranted`;
export const attrUG = `${nsUngranted}/attr/granted`;
export const attrUU = `${nsUngranted}/attr/ungranted`;
export const valGGG = `${attrGG}/value/granted`;
export const valGGU = `${attrGG}/value/ungranted`;
export const valGUG = `${attrGU}/value/granted`;
export const valGUU = `${attrGU}/value/ungranted`;
export const valUGG = `${attrUG}/value/granted`;
export const valUGU = `${attrUG}/value/ungranted`;
export const valUUG = `${attrUU}/value/granted`;
export const valUUU = `${attrUU}/value/ungranted`;

export const kases: Record<string, KeyAccessServer> = Object.fromEntries(
  [
    kasAu,
    kasCa,
    kasUk,
    kasNz,
    kasUs,
    kasUsHCS,
    kasUsSA,
    authority,
    otherAuth,
    specifiedKas,
    evenMoreSpecificKas,
    lessSpecificKas,
  ].map((k) => [
    k,
    {
      $typeName: 'policy.KeyAccessServer',
      id: k,
      kasKeys: [],
      uri: k,
      publicKey: {
        $typeName: 'policy.PublicKey',
        publicKey: {
          case: 'cached',
          value: {
            $typeName: 'policy.KasPublicKeySet',
            keys: [
              {
                $typeName: 'policy.KasPublicKey',
                pem: kasECCert,
                kid: 'e1',
                alg: KasPublicKeyAlgEnum.EC_SECP256R1,
              },
              {
                $typeName: 'policy.KasPublicKey',
                pem: kasPublicKey,
                kid: 'r1',
                alg: KasPublicKeyAlgEnum.RSA_2048,
              },
            ],
          },
        },
      },
      sourceType: SourceType.INTERNAL,
      name: k,
    } as KeyAccessServer,
  ])
);

export const namespaces: Record<string, Namespace> = {};
for (const ns of [nsStandard, nsGranted, nsUngranted]) {
  namespaces[ns] = {
    $typeName: 'policy.Namespace',
    fqn: ns,
    name: ns.split('//')[1],
    active: true,
    grants: [],
    id: '',
    kasKeys: [],
    rootCerts: [],
  };
  if (ns == nsGranted) {
    namespaces[ns]!.grants = [kases[lessSpecificKas]];
  }
}

export const attributes: Record<string, Attribute> = {
  [attrCLS]: {
    fqn: attrCLS,
    namespace: namespaces[nsStandard],
    active: true,
    name: 'Classification',
    rule: AttributeRuleType.UNSPECIFIED,
    $typeName: 'policy.Attribute',
    grants: [],
    id: '',
    kasKeys: [],
    values: [],
  },
  [attrN2K]: {
    fqn: attrN2K,
    namespace: namespaces[nsStandard],
    active: true,
    name: 'Need to Know',
    rule: AttributeRuleType.ALL_OF,
    $typeName: 'policy.Attribute',
    grants: [],
    id: '',
    kasKeys: [],
    values: [],
  },
  [attrREL]: {
    fqn: attrREL,
    namespace: namespaces[nsStandard],
    active: true,
    name: 'Releasable To',
    rule: AttributeRuleType.ANY_OF,
    $typeName: 'policy.Attribute',
    grants: [],
    id: '',
    kasKeys: [],
    values: [],
  },
};
for (const fqn of [attrGG, attrGU, attrUG, attrUU]) {
  const { groups } = fqn.match(/^(?<ns>https?:\/\/[\w./]+)\/attr\/(?<at>\w+)$/) || {};
  if (!groups?.ns || !namespaces[groups.ns] || !groups.at) {
    throw Error(`Invalid fqn [${fqn}]`);
  }
  attributes[fqn] = {
    fqn,
    namespace: namespaces[groups.ns],
    active: true,
    name: groups.at,
    $typeName: 'policy.Attribute',
    grants: [],
    id: '',
    kasKeys: [],
    values: [],
    rule: AttributeRuleType.UNSPECIFIED,
  };
  if (groups.at == 'granted') {
    attributes[fqn].grants = [kases[specifiedKas]];
  }
}

export const values: Record<string, Value> = {};
for (const fqn of [
  valClassA,
  valClassS,
  valClassTS,
  valN2KHCS,
  valN2KINT,
  valN2KSI,
  valRelAus,
  valRelCan,
  valRelGbr,
  valRelNzl,
  valRelUsa,
  valRelFvey,
  valGGG,
  valGGU,
  valGUG,
  valGUU,
  valUGG,
  valUGU,
  valUUG,
  valUUU,
]) {
  const m = fqn.match(/^(https?:\/\/[\w./-]+\/attr\/\S*)\/value\/(\S*)$/);
  if (!m || m.length < 3) {
    throw Error(`invalid attribute value fqn [${fqn}] m:[${m}]`);
  }
  const attribute = attributes[m[1]];
  if (!attribute) {
    throw Error(`unknown attribute [${m[1]}] value fqn [${fqn}]`);
  }
  const value = decodeURIComponent(m[2]);
  if (!value) {
    throw Error(`invalid attribute value fqn [${fqn}]`);
  }
  if (!attribute.values) {
    attribute.values = [];
  }
  let grants: string[] | undefined = undefined;
  switch (m[1]) {
    case attrCLS:
      // defaults only
      break;
    case attrN2K:
      switch (value) {
        case 'INT':
          grants = [kasUk];
          break;
        case 'HCS':
          grants = [kasUsHCS];
          break;
        case 'SI':
          grants = [kasUsSA];
          break;
      }
      break;
    case attrREL:
      switch (value) {
        case 'FVEY':
          grants = [kasAu, kasCa, kasNz, kasUk, kasUs];
          break;
        case 'AUS':
          grants = [kasAu];
          break;
        case 'CAN':
          grants = [kasCa];
          break;
        case 'GBR':
          grants = [kasUk];
          break;
        case 'NZL':
          grants = [kasNz];
          break;
        case 'USA':
          grants = [kasUs];
          break;
      }
      break;
    case attrGG:
    case attrGU:
    case attrUG:
    case attrUU:
      {
        if (value == 'granted') {
          grants = [evenMoreSpecificKas];
        }
      }
      break;
  }

  const val: Value = {
    attribute,
    value,
    fqn,
    active: true,
    id: '',
    kasKeys: [],
    resourceMappings: [],
    subjectMappings: [],
    grants: [],
    obligations: [],
    ...(grants && { grants: grants.map((g) => kases[g]) }),
    $typeName: 'policy.Value',
  };

  values[fqn] = val;
}

export function valueFor(attr: string): Value {
  if (!(attr in values)) {
    throw new Error(`invalid FQN [${attr}]`);
  }
  // console.log('value for', attr, 'is', values[attr]);
  return values[attr];
}

export function valuesFor(attrs: string[]): Value[] {
  return attrs.map(valueFor);
}
