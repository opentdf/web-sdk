import './polyfills.js';
import { createWriteStream, openAsBlob } from 'node:fs';
import { stat, writeFile } from 'node:fs/promises';
import { Writable } from 'node:stream';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import {
  type AuthProvider,
  type CreateOptions,
  type CreateNanoTDFOptions,
  type CreateZTDFOptions,
  type HttpRequest,
  type ReadOptions,
  type Source,
  AuthProviders,
  version,
  OpenTDF,
} from '@opentdf/sdk';
import { CLIError, Level, log } from './logger.js';
import { webcrypto } from 'crypto';
import * as assertions from '@opentdf/sdk/assertions';
import { attributeFQNsAsValues } from '@opentdf/sdk/nano';
import { base64 } from '@opentdf/sdk/encodings';

type AuthToProcess = {
  auth?: string;
  clientId?: string;
  clientSecret?: string;
  concurrencyLimit?: number;
  oidcEndpoint: string;
  userId?: string;
};

type LoggedAuthProvider = AuthProvider & {
  requestLog: HttpRequest[];
};

const bindingTypes = ['ecdsa', 'gmac'];

const containerTypes = ['tdf3', 'nano', 'dataset', 'ztdf'];

const parseJwt = (jwt: string, field = 1) => {
  return JSON.parse(base64.decode(jwt.split('.')[field]));
};

const parseJwtComplete = (jwt: string) => {
  return { header: parseJwt(jwt, 0), payload: parseJwt(jwt) };
};

async function processAuth({
  auth,
  clientId,
  clientSecret,
  concurrencyLimit,
  oidcEndpoint,
  userId,
}: AuthToProcess): Promise<LoggedAuthProvider> {
  log('DEBUG', 'Processing auth params');
  if (auth) {
    log('DEBUG', 'Processing an auth string');
    const authParts = auth.split(':');
    if (authParts.length !== 2) {
      throw new CLIError('CRITICAL', `Auth expects <clientId>:<clientSecret>, received ${auth}`);
    }

    [clientId, clientSecret] = authParts;
  } else if (!clientId || !clientSecret) {
    throw new CLIError(
      'CRITICAL',
      'Auth expects clientId and clientSecret, or combined auth param'
    );
  }
  const actual = await AuthProviders.clientSecretAuthProvider({
    clientId,
    oidcOrigin: oidcEndpoint,
    exchange: 'client',
    clientSecret,
  });
  if (concurrencyLimit !== 1) {
    await actual.oidcAuth.get();
  }
  const requestLog: AuthProviders.HttpRequest[] = [];
  return {
    requestLog,
    updateClientPublicKey: async (signingKey: webcrypto.CryptoKeyPair) => {
      actual.updateClientPublicKey(signingKey);
      log('DEBUG', `updateClientPublicKey: [${signingKey?.publicKey}]`);
    },
    withCreds: async (httpReq: AuthProviders.HttpRequest) => {
      const credible = await actual.withCreds(httpReq);
      if (userId) {
        const url = new URL(credible.url);
        url.searchParams.set('userId', userId);
        credible.url = url.href;
      }
      log('DEBUG', `HTTP Requesting: ${JSON.stringify(credible)}`);
      requestLog.push(credible);
      return credible;
    },
  };
}

const rstrip = (str: string, suffix = ' '): string => {
  while (str && suffix && str.endsWith(suffix)) {
    str = str.slice(0, -suffix.length);
  }
  return str;
};

async function parseReadOptions(argv: Partial<mainArgs>): Promise<ReadOptions> {
  const r: ReadOptions = { source: await fileAsSource(argv.file as string) };
  if (argv.noVerifyAssertions) {
    r.noVerify = true;
  }
  if (argv.concurrencyLimit !== undefined) {
    r.concurrencyLimit = argv.concurrencyLimit;
  } else {
    r.concurrencyLimit = 100;
  }
  return r;
}

function parseAssertionConfig(s: string): assertions.AssertionConfig[] {
  const u = JSON.parse(s);
  // if u is null or empty, return an empty array
  if (!u) {
    return [];
  }
  const a = Array.isArray(u) ? u : [u];
  for (const assertion of a) {
    if (!assertions.isAssertionConfig(assertion)) {
      throw new CLIError('CRITICAL', `invalid assertion config ${JSON.stringify(assertion)}`);
    }
  }
  return a;
}

async function parseCreateOptions(argv: Partial<mainArgs>): Promise<CreateOptions> {
  const c: CreateOptions = {
    source: { type: 'file-browser', location: await openAsBlob(argv.file as string) },
  };
  if (argv.attributes?.length) {
    c.attributes = argv.attributes.split(',');
  }
  c.autoconfigure = !!argv.autoconfigure;
  return c;
}

async function parseCreateZTDFOptions(argv: Partial<mainArgs>): Promise<CreateZTDFOptions> {
  const c: CreateZTDFOptions = await parseCreateOptions(argv);
  if (argv.assertions?.length) {
    c.assertionConfigs = parseAssertionConfig(argv.assertions);
  }
  if (argv.mimeType?.length) {
    if (argv.mimeType && /^[a-z]+\/[a-z0-9-+.]+$/.test(argv.mimeType)) {
      c.mimeType = argv.mimeType as `${string}/${string}`;
    } else {
      throw new CLIError('CRITICAL', 'Invalid mimeType format');
    }
  }
  return c;
}

async function parseCreateNanoTDFOptions(argv: Partial<mainArgs>): Promise<CreateZTDFOptions> {
  const c: CreateNanoTDFOptions = await parseCreateOptions(argv);
  const ecdsaBinding = argv.policyBinding?.toLowerCase() == 'ecdsa';
  if (ecdsaBinding) {
    c.bindingType = 'ecdsa';
  }
  return c;
}

async function fileAsSource(file: string): Promise<Source> {
  if (!file) {
    throw new CLIError('CRITICAL', 'Must specify file or pipe');
  }
  try {
    const stats = await stat(file);
    if (!stats?.isFile()) {
      throw new CLIError('CRITICAL', `File does not exist [${file}]`);
    }
  } catch (e) {
    throw new CLIError('CRITICAL', `File is not accessable [${file}]`);
  }
  log('DEBUG', `Using input from file [${file}]`);
  return { type: 'file-browser', location: await openAsBlob(file) };
}

export const handleArgs = (args: string[]) => {
  return (
    yargs(args)
      .middleware((argv) => {
        if (argv.silent) {
          log.level = 'CRITICAL';
        } else if (argv.logLevel) {
          const ll = argv.logLevel as string;
          log.level = ll.toUpperCase() as Level;
        }
      })
      .fail((msg, err, yargs) => {
        if (err instanceof CLIError) {
          log(err);
          process.exit(1);
        } else if (err) {
          log(err);
          process.exit(2);
        } else {
          console.error(`${msg}\n\n${yargs.help()}`);
          process.exit(1);
        }
      })

      // AUTH OPTIONS
      .option('kasEndpoint', {
        demandOption: true,
        group: 'Server Endpoints:',
        type: 'string',
        description: 'URL to non-default KAS instance (https://mykas.net)',
      })
      .option('oidcEndpoint', {
        demandOption: true,
        group: 'Server Endpoints:',
        type: 'string',
        description: 'URL to non-default OIDC IdP (https://myidp.net)',
      })
      .option('policyEndpoint', {
        group: 'Server Endpoints:',
        type: 'string',
        description: 'Attribute and key grant service endpoint',
      })
      .option('allowList', {
        group: 'Security:',
        desc: 'allowed KAS origins, comma separated; defaults to [kasEndpoint]',
        type: 'string',
        validate: (uris: string) => uris.split(','),
      })
      .option('ignoreAllowList', {
        group: 'Security:',
        desc: 'disable KAS allowlist feature for decrypt',
        type: 'boolean',
      })
      .option('noVerifyAssertions', {
        alias: 'no-verify-assertions',
        group: 'Decrypt',
        desc: 'Do not verify assertions',
        type: 'boolean',
      })
      .option('concurrencyLimit', {
        alias: 'concurrency-limit',
        group: 'Decrypt',
        desc: 'Enable concurrent key split and share lookups',
        type: 'number',
      })
      .option('auth', {
        group: 'OAuth and OIDC:',
        type: 'string',
        description: 'Combined OAuth Client Credentials (<clientId>:<clientSecret>)',
      })
      .option('dpop', {
        group: 'Security:',
        desc: 'Use DPoP for token binding',
        type: 'boolean',
      })
      .implies('auth', '--no-clientId')
      .implies('auth', '--no-clientSecret')

      .option('clientId', {
        group: 'OAuth and OIDC:',
        alias: 'cid',
        type: 'string',
        description: 'OAuth Client Credentials: IdP-issued Client ID',
      })
      .implies('clientId', 'clientSecret')

      .option('clientSecret', {
        group: 'OAuth and OIDC:',
        alias: 'cs',
        type: 'string',
        description: 'OAuth Client Credentials: IdP-issued Client Secret',
      })
      .implies('clientSecret', 'clientId')

      .option('exchangeToken', {
        group: 'OAuth and OIDC:',
        alias: 'et',
        type: 'string',
        description: 'OAuth Token Exchange: Token issued by trusted external IdP',
      })
      .implies('exchangeToken', 'clientId')

      // Examples
      .example('$0 --auth ClientID123:Cli3nt$ecret', '# OIDC client credentials')

      .example('$0 --clientId ClientID123 --clientSecret Cli3nt$ecret', '# OIDC client credentials')

      // Policy, encryption, and container options
      .options({
        assertions: {
          group: 'Encrypt Options:',
          desc: 'ZTDF assertion config objects',
          type: 'string',
          default: '',
          validate: parseAssertionConfig,
        },
        attributes: {
          group: 'Encrypt Options:',
          desc: 'Data attributes for the policy',
          type: 'string',
          default: '',
          validate: (attributes: string) => attributes.split(','),
        },
        autoconfigure: {
          group: 'Encrypt Options:',
          desc: 'Enable automatic configuration from attributes using policy service',
          type: 'boolean',
          default: false,
        },
        containerType: {
          group: 'Encrypt Options:',
          alias: 't',
          choices: containerTypes,
          description: 'Container format',
          default: 'nano',
        },
        policyBinding: {
          group: 'Encrypt Options:',
          choices: bindingTypes,
          description: 'Policy Binding Type (nano only)',
          default: 'gmac',
        },
        mimeType: {
          group: 'Encrypt Options:',
          desc: 'Mime type for the plain text file (only supported for ztdf)',
          type: 'string',
          default: '',
        },
        userId: {
          group: 'Encrypt Options:',
          type: 'string',
          description: 'Owner email address',
        },
      })

      // COMMANDS
      .options({
        logLevel: {
          group: 'Verbosity:',
          alias: 'log-level',
          type: 'string',
          default: 'info',
          desc: 'Set logging level',
        },
        silent: {
          group: 'Verbosity:',
          type: 'boolean',
          default: false,
          desc: 'Disable logging',
        },
      })
      .option('output', {
        type: 'string',
        description: 'output file',
      })

      .command(
        'attrs',
        'Look up defintions of attributes',
        (yargs) => {
          yargs.strict();
        },
        async (argv) => {
          log('DEBUG', 'attribute value lookup');
          const authProvider = await processAuth(argv);
          const signingKey = await crypto.subtle.generateKey(
            {
              name: 'RSASSA-PKCS1-v1_5',
              hash: 'SHA-256',
              modulusLength: 2048,
              publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            },
            true,
            ['sign', 'verify']
          );
          authProvider.updateClientPublicKey(signingKey);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);

          const policyUrl: string = guessPolicyUrl(argv);
          const defs = await attributeFQNsAsValues(
            policyUrl,
            authProvider,
            ...(argv.attributes as string).split(',')
          );
          console.log(JSON.stringify(defs, null, 2));
        }
      )

      .command(
        'decrypt [file]',
        'Decrypt TDF to string',
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        (yargs) => {
          yargs.strict().positional('file', {
            describe: 'path to plain text file',
            type: 'string',
          });
        },
        async (argv) => {
          log('DEBUG', 'Running decrypt command');
          const allowedKases = argv.allowList?.split(',');
          const ignoreAllowList = !!argv.ignoreAllowList;
          const authProvider = await processAuth(argv);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);
          const client = new OpenTDF({
            authProvider,
            defaultCreateOptions: {
              defaultKASEndpoint: argv.kasEndpoint,
            },
            defaultReadOptions: {
              allowedKASEndpoints: allowedKases,
              ignoreAllowlist: ignoreAllowList,
              noVerify: !!argv.noVerifyAssertions,
            },
            disableDPoP: !argv.dpop,
            policyEndpoint: guessPolicyUrl(argv),
          });
          log('SILLY', `Initialized client ${JSON.stringify(client)}`);

          log('DEBUG', `About to TDF3 decrypt [${argv.file}]`);
          const ct = await client.read(await parseReadOptions(argv));
          const destination = createWriteStream(argv.output as string);
          await ct.pipeTo(Writable.toWeb(destination));
          const lastRequest = authProvider.requestLog[authProvider.requestLog.length - 1];
          let accessToken = null;
          let dpopToken = null;
          for (const h of Object.keys(lastRequest.headers)) {
            switch (h.toLowerCase()) {
              case 'dpop':
                console.assert(!dpopToken, 'Multiple dpop headers found');
                dpopToken = parseJwtComplete(lastRequest.headers[h]);
                log('INFO', `dpop: ${JSON.stringify(dpopToken)}`);
                break;
              case 'authorization':
                console.assert(!accessToken, 'Multiple authorization headers found');
                accessToken = parseJwt(lastRequest.headers[h].split(' ')[1]);
                log('INFO', `Access Token: ${JSON.stringify(accessToken)}`);
                if (argv.dpop) {
                  console.assert(accessToken.cnf?.jkt, 'Access token must have a cnf.jkt');
                }
                break;
            }
          }
          console.assert(accessToken, 'No access_token found');
          console.assert(!argv.dpop || dpopToken, 'DPoP requested but absent');
        }
      )
      .command(
        'encrypt [file]',
        'Encrypt file or pipe to a TDF',
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        (yargs) => {
          yargs.strict().positional('file', {
            describe: 'path to plain text file',
            type: 'string',
          });
        },
        async (argv) => {
          log('DEBUG', 'Running encrypt command');
          const authProvider = await processAuth(argv);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);

          const client = new OpenTDF({
            authProvider,
            defaultCreateOptions: {
              defaultKASEndpoint: argv.kasEndpoint,
            },
            disableDPoP: !argv.dpop,
            policyEndpoint: guessPolicyUrl(argv),
          });
          log('SILLY', `Initialized client ${JSON.stringify(client)}`);

          if ('tdf3' === argv.containerType || 'ztdf' === argv.containerType) {
            log('DEBUG', `TDF3 Create`);
            const ct = await client.createZTDF(await parseCreateZTDFOptions(argv));
            if (!ct) {
              throw new CLIError('CRITICAL', 'Encrypt configuration error: No output?');
            }
            const destination = createWriteStream(argv.output as string);
            await ct.pipeTo(Writable.toWeb(destination));
          } else {
            log('SILLY', `Initialized client ${JSON.stringify(client)}`);

            const cyphertext = await client.createNanoTDF(await parseCreateNanoTDFOptions(argv));

            log('DEBUG', `Handle cyphertext output ${JSON.stringify(cyphertext)}`);
            if (argv.output) {
              await writeFile(argv.output, new Uint8Array(cyphertext));
            } else {
              console.log(base64.encodeArrayBuffer(cyphertext));
            }
          }
        }
      )
      .usage('openTDF CLI\n\nUsage: $0 [options]')
      .alias('help', 'h')
      .demandCommand()
      .recommendCommands()
      .help('help')
      .options({
        env: {
          desc: 'Set the environment',
        },
      })

      .version(
        'version',
        JSON.stringify({
          '@opentdf/ctl': process.env.npm_package_version || 'UNRELEASED',
          '@opentdf/sdk': version,
        })
      )
      .alias('version', 'V')
      .strict()
      .parseAsync()
  );
};

export type mainArgs = Awaited<ReturnType<typeof handleArgs>>;
export const main = async (argsPromise: mainArgs) => {
  argsPromise;
};

handleArgs(hideBin(process.argv))
  .then(main)
  .then(() => {
    // Nothing;
  })
  .catch((err) => {
    console.error(err);
  });

function guessPolicyUrl({
  kasEndpoint,
  policyEndpoint,
}: {
  kasEndpoint: string;
  policyEndpoint?: string;
}) {
  let policyUrl: string;
  if (policyEndpoint) {
    policyUrl = rstrip(policyEndpoint, '/');
  } else {
    const uNoSlash = rstrip(kasEndpoint, '/');
    policyUrl = uNoSlash.endsWith('/kas') ? uNoSlash.slice(0, -4) : uNoSlash;
  }
  return policyUrl;
}
