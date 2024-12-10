import { SignJWT, importPKCS8, JWTPayload } from 'jose';
import { v4 } from 'uuid';

import { AttributeObject } from '../../src/tdf/AttributeObject.js';
import { toCryptoKeyPair } from '../../tdf3/src/crypto/crypto-utils.js';
import { AttributeSet } from '../../tdf3/src/models/attribute-set.js';
import {
  entityECPrivateKey,
  entityECPublicKey,
  entityPrivateKey,
  entityPublicKey,
  extraECPrivateKey,
  extraECPublicKey,
  kasECCert,
  kasECPrivateKey,
  kasPrivateKey,
  kasPublicKey,
} from './pems.js';

type CreateAttributePayload = {
  attribute: string;
  displayName: string;
  pubKey: string;
  kasUrl: string;
  isDefault: string;
};

type CreateJwtAttributeContext = {
  aaPrivateKey: string;
  createAttribute: (prop: CreateAttributePayload) => JWTPayload;
};

type createAttributeSetContext = {
  createAttribute: (prop: CreateAttributePayload) => AttributeObject;
};

type GetPolicyObjectContext = {
  getUserId: () => string;
};

type GetScopeContext = {
  getUserId: () => string;
};

function getKasUrl() {
  return 'http://local.virtru.com:4000'; // Sensitive
}

export function getMocks() {
  return Object.create({
    kasPrivateKey,
    kasPublicKey,
    // TODO: diff key then KAS
    aaPrivateKey: `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC3GdLoh0BHjsu9
doR2D3+MekHB9VR/cmqV7v6R7xEWZJkuymrJzPy8reKSLK7yDhUEZNA9jslVReMp
QHaR0/ND0fevJZ0yoo8IXGSIYv+prX6wZbqp4YkcahWMx5nFzpCDSJfd2ZBnCvns
z4x95eX8jme9qNYcELFDEkeLFCushNLXdg8NKrWh/Ew8VEZGf4hmtb30J11Uj5P2
cv6zgATpa6xqjpg8hUarQYTyQi01DTKZ9iR8Kw/xAH+ocXtbJdy046bMb9uMpeJ/
LlMpELSN5pqamVJis/NkWJOVRdwD//p7WQdz9T4TGzvvrO8KUQoORYERf0EtwBtu
fv5SDpNhAgMBAAECggEBAI7tk5t76ItzRktRNrlKA9DOpoIXVaxeziDX/NRB/96x
DHpf+9gnMaq/ObvNMYs1vuY9I+jJixQLh/VtoqDXCHAKeQO5ouohxvFJ3hgw302+
ZsSfxIRTz8nkbYoFTV4BjwFMK3A8IuKsyMc4hHzKdyscppKANxKVXSn0HPDOAAGc
Ivdah2o68kef3eeMxwwxEjUCGbv98AsnXOcygb41ZOTFdWjnSZ9/aV2EVTmNs6lL
hU9uD2RTsz7ohbaM2abDeRNCDlQNQe7eQS8B6mItSPahg4eeYC1at2ZbYIcDchUj
Iqz4fMiuAInLNahua6wjN2P9v6wHFax/WXsxTHiHgyECgYEA4nsaTllXq/8ZtK1U
D7e9mqiipKPf/JcHBrG20kSwAgGtzXh0qeVl/KKfSGzTYUF91+q0/XjLvQeaVpDo
VQShe09mAjDPOnqgqV8dqsNRP49JlnkF3V83pBrmMjXDAzA552RwkwZmNQegU19V
jtIsEQQheFe5ZrrzBsc4wd4BFu0CgYEAzvdHLAlki2E9lDqRcwMsJNE4AWS8u+ZR
4G8VLo+fr6qHmv+HYM9vjPvnoS8yiorywLQaBCSDmxPvY9Wy7ErSZ799LLgSpx1e
Z/KFr9VFYZQ+Y0Dm9OPOHPCzOqjNJwdKNsIaRuKAL+NCJQZ1MyZJC3VsThf8gnfm
cQvnK3ryy8UCgYEAhlRLkwLsvCgvP/m6LSRnAg9ZgFtuY6vUUAUiEW8KEfaa9o6m
a4qTRhfSb6uUaE/m6yTbuqdl+DVFNmj2VE7N1IyQTWZT0zSejDbNKtZ0H0XGeMhJ
UTbDksMdm9RFWWPGRFdPafTWtEdUsX6PCYng9yrDC1TEs4jY0kFhiaM6dDUCgYB6
X19nvE4E04QzhsXFeVS6mDJDMKsfdrlmuIePtkA2/9+aWAhVx5EvjSqR9XQu0qVi
J5tSY7ylDw52uz5F1J+/1EtRC62LviO51n4RT0rsvVh+Gzv0BFY0amWvA2v57aeF
5RLgYsBkkDzl44GcssBx1AYrzqbxBa/tm5od7V5t+QKBgQCdR+BwAsIHF2KzRQhW
BK7+TM6jTOpG5CmxyHhalOdGc56l67NPw10FIZx7zGihAzYbyRv4IBUj2R3nTASb
7uDr0bAL0hHapZgRGzQPG0WX3ifFcfJ+LZoRklm/jHMxYGC/XrCtCfL3ROBL8rcF
3JkIg040ZMZ8wNzpy8zgA7D3KA==
-----END PRIVATE KEY-----`,
    aaPublicKey: `-----BEGIN CERTIFICATE-----
MIIDsTCCApmgAwIBAgIJAONESzw+N+3SMA0GCSqGSIb3DQEBDAUAMHUxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJEQzETMBEGA1UEBwwKV2FzaGluZ3RvbjEPMA0GA1UE
CgwGVmlydHJ1MREwDwYDVQQDDAhhY2NvdW50czEgMB4GCSqGSIb3DQEJARYRZGV2
b3BzQHZpcnRydS5jb20wIBcNMTgxMDE4MTY1MjIxWhgPMzAxODAyMTgxNjUyMjFa
MHUxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJEQzETMBEGA1UEBwwKV2FzaGluZ3Rv
bjEPMA0GA1UECgwGVmlydHJ1MREwDwYDVQQDDAhhY2NvdW50czEgMB4GCSqGSIb3
DQEJARYRZGV2b3BzQHZpcnRydS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC3GdLoh0BHjsu9doR2D3+MekHB9VR/cmqV7v6R7xEWZJkuymrJzPy8
reKSLK7yDhUEZNA9jslVReMpQHaR0/ND0fevJZ0yoo8IXGSIYv+prX6wZbqp4Ykc
ahWMx5nFzpCDSJfd2ZBnCvnsz4x95eX8jme9qNYcELFDEkeLFCushNLXdg8NKrWh
/Ew8VEZGf4hmtb30J11Uj5P2cv6zgATpa6xqjpg8hUarQYTyQi01DTKZ9iR8Kw/x
AH+ocXtbJdy046bMb9uMpeJ/LlMpELSN5pqamVJis/NkWJOVRdwD//p7WQdz9T4T
GzvvrO8KUQoORYERf0EtwBtufv5SDpNhAgMBAAGjQjBAMB0GA1UdDgQWBBTVPQ3Y
oYYXHWbZfK2sonPrOE7nszAfBgNVHSMEGDAWgBTVPQ3YoYYXHWbZfK2sonPrOE7n
szANBgkqhkiG9w0BAQwFAAOCAQEAT2ZjAJPQSf0tME0vbAqHzB8iIhR5KniGgJMJ
mRrXbTl2HBH6WnRwfgY1Ok1X224ph4uBGaAUGs8ONBKli0673jE+IgVob7TCu2yV
gHaKcybDegK4esVNRdsDmOWT+eTxGYAzejdIgdFo6R7Xvs87RbqwM4Cko4xoWGVF
ghWsBqUmyg/rZoggL5H1V166hvoLPKU7SrCInZ8Wd6x4rsNDaxNiC9El102pKXu4
wCiqJZ0XwklGkH9X0Z5x0txc68tqmSlE/z4i/96oxMp0C2thWfy90ub85f5FrB9m
tN5S0umLPkMUJ6zBIxh1RQK1ZYjfuKij+EEimbqtte9rYyQr3Q==
-----END CERTIFICATE-----`,
    entityPrivateKey,
    entityPublicKey,

    entityECPrivateKey,
    entityECPublicKey,

    extraECPrivateKey,
    extraECPublicKey,

    kasECCert,
    kasECPrivateKey,

    async entityKeyPair(): Promise<CryptoKeyPair> {
      return toCryptoKeyPair({
        privateKey: entityPrivateKey,
        publicKey: entityPublicKey,
      });
    },

    async entityECKeyPair(): Promise<CryptoKeyPair> {
      return toCryptoKeyPair({
        privateKey: entityECPrivateKey,
        publicKey: entityECPublicKey,
      });
    },

    async extraECKeyPair(): Promise<CryptoKeyPair> {
      return toCryptoKeyPair({
        privateKey: extraECPrivateKey,
        publicKey: extraECPublicKey,
      });
    },

    createAttribute({
      attribute = 'https://api.virtru.com/attr/default/value/default',
      displayName = 'Default Attribute',
      pubKey = kasPublicKey,
      kasUrl = getKasUrl(),
      isDefault = 'not set',
    }: CreateAttributePayload) {
      if (isDefault === 'not set') {
        // If none of the options are specified this creates a default attribute
        return { attribute, displayName, pubKey, kasUrl };
      }
      return { attribute, displayName, pubKey, kasUrl, isDefault };
    },

    async createJwtAttribute(this: CreateJwtAttributeContext, options: CreateAttributePayload) {
      // If none of the options are specified this creates a default attribute
      try {
        const attrObj = this.createAttribute(options);

        const pkKeyLike = await importPKCS8(this.aaPrivateKey, 'RS256');

        const jwt = await new SignJWT(attrObj)
          .setProtectedHeader({ alg: 'RS256' })
          .setIssuedAt()
          .setExpirationTime('2h')
          .sign(pkKeyLike);

        return { jwt };
      } catch (e) {
        console.log('Mocks.createJwtAttribute failed', e);
        return {};
      }
    },

    async createAttributeSet(
      this: createAttributeSetContext,
      arrayOfAttrOptions: CreateAttributePayload[] = []
    ) {
      const aSet = new AttributeSet();
      const attributes = arrayOfAttrOptions.map((options) => this.createAttribute(options));
      aSet.addAttributes(attributes);
      return aSet;
    },

    getUserId() {
      return 'user@domain.com';
    },

    getMetadataObject() {
      const baseObject = {
        connectOptions: {
          testUrl: 'http://testurl.com', // Sensitive
        },
        policyObject: {},
      };

      return baseObject;
    },

    getPolicyObject(this: GetPolicyObjectContext) {
      const userId = this.getUserId();
      const baseObject = {
        uuid: v4(),
        body: {
          dataAttributes: [],
          dissem: [userId],
        },
      };

      return baseObject;
    },

    getScope(this: GetScopeContext) {
      const userId = this.getUserId();
      return {
        attributes: [],
        dissem: [userId],
      };
    },

    getKasUrl,
  });
}
