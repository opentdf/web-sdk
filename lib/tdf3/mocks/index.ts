import { SignJWT, importPKCS8 } from 'jose';
import { AttributeSet } from '../src/models/attribute-set.js';
import { v4 } from 'uuid';

type CreateAttributePayload = {
  attribute: string;
  displayName: string;
  pubKey: string;
  kasUrl: string;
  isDefault: string;
};

type CreateJwtAttributeContext = {
  aaPrivateKey: string;
  createAttribute: (prop: CreateAttributePayload) => CreateAttributePayload;
};

type createAttributeSetContext = {
  createAttribute: (prop: CreateAttributePayload) => CreateAttributePayload;
};

type GetEntityObjectContext = {
  aaPrivateKey: string;
  entityPublicKey: string;
  createJwtAttribute: (prop: CreateAttributePayload) => Promise<{ jwt?: string }>;
  getUserId: () => string;
};

type GetPolicyObjectContext = {
  getUserId: () => string;
};

type GetScopeContext = {
  getUserId: () => string;
};

export default function getMocks() {
  return Object.create({
    // TODO: diff key then KAS
    kasPrivateKey: `-----BEGIN PRIVATE KEY-----
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
    kasPublicKey: `-----BEGIN CERTIFICATE-----
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
    entityPrivateKey: `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDLXwR+Lr7e9IQu
lsrnyAID28nFm2hEdHrTjKLvTuHqfNOxNI1SDmY3O3+dazBbOWghYKADsQ82knL2
VifiHVnouHESB/TAVxq7HT8LX10LpZE93onoQjvPvvqC2hJX+EA1QEZKNpJgI58B
VgTxJnYXNvp8SHFpXP7V0RWFPV0GzNt6zH9qJwIn/u8KaXAR5QfCOyLyb0LM9M9y
MSNuseLvBhSP/Ju+kzf1mDBFGBn9cZdmx0vGJsmKXHWhLmBj0iilxShaLt3ejsm4
x0ExnSPGRWCvaGJQeptt9ETNnFnX8SjBd/3AmJebf/l4IABr7aRNw6u5xlfM07gn
fwKgXP/DAgMBAAECggEADInMpJzsLqHDnn20f8rAeQ1taK32pTXLNsy2ZOunmQXe
JVA4oET7/06/ROzNW+pzpY8n/mJFrlckGFTie5nUp7jrW7G64LreDog0kVZtTaEF
DdvxA61Fs76yAixAskS/bKkMTFoF90Bq9rGfd2CoKjE9CzmKKHVPzs3ntkG8wQT3
C1ClT8Ce4Y+aNjLd+i47xIxNenHKfezZOriteKxVWna23fl3ISXr7e1LDI75qhcY
l3NY+EtwHKm2tGW5ukGUsNqkFRIW+kulclb+xpaL/hRKf+FiE4h/0B5MLN8eVXNf
8z2A31cbXRTqzcDYLRuz1ykHfBX6ZG/6eL3t+VqCEQKBgQD44o5kdM8mIcxcruI7
TT5tE/cUr4CQnus6NEbMj8WpfGG17GBVVIy/6cXh8+UhiFHbWAJb1wXejs9vUZZw
6hE7uWcOuwoY5F7hl9idWryrIUut+7a8YASYTDMrI77p7Sjin5NQvRppyH1io1Yi
fl9+8MJ5FQYVTI3OnqI3v/hBEwKBgQDRL19MEVH9h4NmXh7wRkz0iXM5dM9mpI9C
daUjv/wH2dlI5SpZkqqgOZ2X2qdgrZdwX33q2z1nSRzbWMjvcfDkJvwexZ995XYH
ffI2Yd1sydUCLJ796vnGphJOpvasKqqIjnYDWXi/uhepw7xYJkTPzmy1P/MzjcbS
JDEsHSfMkQKBgF9rTLhK6FhwQM+P5QBjXvmm2+W8W4gWxYxtGm+290tBepyq4UwV
vFifodQ9E63Fe8yic1UOnRt0mSbOmuTzeGPzcwV8xCRC+fV3p/68GPVrMH6lsKuM
DHbvT/bMH5fD6xbnoy0jMws3aIr2oEFdPfOHDqgpXUmxLfT3cK37FYytAoGAU1/n
QsFQhZViiQWQnUHX4Et8cnUdSRLjyqBrTqFxiYuJsCUuyP7NJQlxx5mtxrnJt09I
N7hkc+tPJhnwFIe8dKMZMAaieCJh9cB8LrK492hGjxRL1na2UTfV6iVgAeULjVwC
q3kYyIoabl6GjjfKi20CJQe1HmIu0Yj9VFDWkRECgYAe0j6P2Kkb/BBdVArme1PK
at1tabfCj99bPEIJgMN0ASU5WU34PVPx4TPiYO40t/ckprslBJAqS4uDwhltiw7q
oFbMAKcie6QXgQkuVPwVjVw6tyJz4mWO8k+XU+9eC+lDq0KHMvXDDabtjYVBQR8g
V5v5HTYXvWh5SG1ZrFLLmw==
-----END PRIVATE KEY-----`,
    entityPublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy18Efi6+3vSELpbK58gC
A9vJxZtoRHR604yi707h6nzTsTSNUg5mNzt/nWswWzloIWCgA7EPNpJy9lYn4h1Z
6LhxEgf0wFcaux0/C19dC6WRPd6J6EI7z776gtoSV/hANUBGSjaSYCOfAVYE8SZ2
Fzb6fEhxaVz+1dEVhT1dBszbesx/aicCJ/7vCmlwEeUHwjsi8m9CzPTPcjEjbrHi
7wYUj/ybvpM39ZgwRRgZ/XGXZsdLxibJilx1oS5gY9IopcUoWi7d3o7JuMdBMZ0j
xkVgr2hiUHqbbfREzZxZ1/EowXf9wJiXm3/5eCAAa+2kTcOrucZXzNO4J38CoFz/
wwIDAQAB
-----END PUBLIC KEY-----`,
    createAttribute({
      attribute = 'https://api.virtru.com/attr/default/value/default',
      displayName = 'Default Attribute', // @ts-ignore
      pubKey = this.kasPublicKey, // @ts-ignore
      kasUrl = this.getKasUrl(),
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

    async createAttributeSet(this: createAttributeSetContext, arrayOfAttrOptions = []) {
      const aSet = new AttributeSet();
      const attributes = arrayOfAttrOptions.forEach((options) => this.createAttribute(options));
      // @ts-ignore
      aSet.addAttributes(attributes);
      return aSet;
    },

    async getEntityObject(this: GetEntityObjectContext, attributes = []) {
      const jwtAttributes = await Promise.all(
        attributes.map(async (options) => {
          const attrJwt = await this.createJwtAttribute(options);
          return attrJwt;
        })
      );
      const baseObject = {
        userId: this.getUserId(),
        aliases: [],
        attributes: jwtAttributes,
        publicKey: this.entityPublicKey,
      };

      const pkKeyLike = await importPKCS8(this.aaPrivateKey, 'RS256');

      // @ts-ignore
      baseObject.cert = await new SignJWT(baseObject)
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .setExpirationTime('24h')
        .sign(pkKeyLike);

      return baseObject;
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

    getKasUrl() {
      return 'http://local.virtru.com:4000'; // Sensitive
    },
  });
}
