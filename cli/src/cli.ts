import './polyfills.js';
import { openAsBlob } from 'node:fs';
import { open, readFile, stat, writeFile } from 'node:fs/promises';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import {
  type AuthProvider,
  type EncryptParams,
  type HttpRequest,
  AuthProviders,
  NanoTDFClient,
  NanoTDFDatasetClient,
  TDF3Client,
  version,
  EncryptParamsBuilder,
  DecryptParams,
  DecryptParamsBuilder,
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

type AnyNanoClient = NanoTDFClient | NanoTDFDatasetClient;

function addParams(client: AnyNanoClient, argv: Partial<mainArgs>) {
  if (argv.attributes?.length) {
    client.dataAttributes = argv.attributes.split(',');
  }
  if (argv.usersWithAccess?.length) {
    client.dissems = argv.usersWithAccess.split(',');
  }
  log('SILLY', `Built encrypt params dissems: ${client.dissems}, attrs: ${client.dataAttributes}`);
}

async function tdf3DecryptParamsFor(argv: Partial<mainArgs>): Promise<DecryptParams> {
  const c = new DecryptParamsBuilder();
  if (argv.noVerifyAssertions) {
    c.withNoVerifyAssertions(true);
  }
  c.setFileSource(await openAsBlob(argv.file as string));
  return c.build();
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

async function tdf3EncryptParamsFor(argv: Partial<mainArgs>): Promise<EncryptParams> {
  const c = new EncryptParamsBuilder();
  if (argv.assertions?.length) {
    c.withAssertions(parseAssertionConfig(argv.assertions));
  }
  if (argv.attributes?.length) {
    c.setAttributes(argv.attributes.split(','));
  }
  if (argv.usersWithAccess?.length) {
    c.setUsersWithAccess(argv.usersWithAccess.split(','));
  }
  if (argv.mimeType?.length) {
    c.setMimeType(argv.mimeType);
  }
  if (argv.autoconfigure) {
    c.withAutoconfigure();
  }
  // use offline mode, we do not have upsert for v2
  c.setOffline();
  // FIXME TODO must call file.close() after we are done
  const buffer = await processDataIn(argv.file as string);
  c.setBufferSource(buffer);
  return c.build();
}

async function processDataIn(file: string) {
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
  return readFile(file);
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
        group: 'Security',
        desc: 'Do not verify assertions',
        type: 'boolean',
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
        usersWithAccess: {
          alias: 'users-with-access',
          group: 'Encrypt Options:',
          desc: 'Add users to the policy',
          type: 'string',
          default: '',
          validate: (users: string) => users.split(','),
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

          const kasEndpoint = argv.kasEndpoint;
          if (argv.containerType === 'tdf3' || argv.containerType == 'ztdf') {
            log('DEBUG', `TDF3 Client`);
            const client = new TDF3Client({
              allowedKases,
              ignoreAllowList,
              authProvider,
              kasEndpoint,
              dpopEnabled: argv.dpop,
            });
            log('SILLY', `Initialized client ${JSON.stringify(client)}`);
            log('DEBUG', `About to decrypt [${argv.file}]`);
            const ct = await client.decrypt(await tdf3DecryptParamsFor(argv));
            if (argv.output) {
              const filehandle = await open(argv.output, 'w');
              await filehandle.writeFile(ct.stream);
            } else {
              console.log(await ct.toString());
            }
          } else {
            const dpopEnabled = !!argv.dpop;
            const client =
              argv.containerType === 'nano'
                ? new NanoTDFClient({
                    allowedKases,
                    ignoreAllowList,
                    authProvider,
                    kasEndpoint,
                    dpopEnabled,
                  })
                : new NanoTDFDatasetClient({
                    allowedKases,
                    ignoreAllowList,
                    authProvider,
                    kasEndpoint,
                    dpopEnabled,
                  });
            const buffer = await processDataIn(argv.file as string);

            log('DEBUG', 'Decrypt data.');
            const plaintext = await client.decrypt(buffer);

            log('DEBUG', 'Handle output.');
            if (argv.output) {
              await writeFile(argv.output, new Uint8Array(plaintext));
            } else {
              console.log(new TextDecoder().decode(plaintext));
            }
          }
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
          const kasEndpoint = argv.kasEndpoint;
          const ignoreAllowList = !!argv.ignoreAllowList;
          const allowedKases = argv.allowList?.split(',');

          if ('tdf3' === argv.containerType || 'ztdf' === argv.containerType) {
            log('DEBUG', `TDF3 Client`);
            const policyEndpoint: string = guessPolicyUrl(argv);
            const client = new TDF3Client({
              allowedKases,
              ignoreAllowList,
              authProvider,
              kasEndpoint,
              policyEndpoint,
              dpopEnabled: argv.dpop,
            });
            log('SILLY', `Initialized client ${JSON.stringify(client)}`);
            const ct = await client.encrypt(await tdf3EncryptParamsFor(argv));
            if (!ct) {
              throw new CLIError('CRITICAL', 'Encrypt configuration error: No output?');
            }
            if (argv.output) {
              const filehandle = await open(argv.output, 'w');
              await filehandle.writeFile(ct.stream);
            } else {
              console.log(await ct.toString());
            }
          } else {
            const dpopEnabled = !!argv.dpop;
            const ecdsaBinding = argv.policyBinding.toLowerCase() == 'ecdsa';
            const client =
              argv.containerType === 'nano'
                ? new NanoTDFClient({ allowedKases, authProvider, dpopEnabled, kasEndpoint })
                : new NanoTDFDatasetClient({
                    allowedKases,
                    authProvider,
                    dpopEnabled,
                    kasEndpoint,
                  });
            log('SILLY', `Initialized client ${JSON.stringify(client)}`);

            addParams(client, argv);

            const buffer = await processDataIn(argv.file as string);
            const cyphertext = await client.encrypt(buffer, { ecdsaBinding });

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
