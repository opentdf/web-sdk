import yargs from 'yargs';
import { readFile, stat, writeFile } from 'fs/promises';
import { hideBin } from 'yargs/helpers';
import {
  FileClient,
  NanoTDFClient,
  NanoTDFDatasetClient,
  AuthProviders,
  version,
} from '@opentdf/client';
import { CLIError, Level, log } from './logger.js';
import { webcrypto } from 'crypto';

type AuthToProcess = {
  auth?: string;
  clientId?: string;
  clientSecret?: string;
  oidcEndpoint: string;
  userId?: string;
};

const containerTypes = ['tdf3', 'nano', 'dataset'] as const;

const parseJwt = (jwt: string, field = 1) => {
  return JSON.parse(Buffer.from(jwt.split('.')[field], 'base64').toString());
};
const parseJwtComplete = (jwt: string) => {
  return { header: parseJwt(jwt, 0), payload: parseJwt(jwt) };
};

async function processAuth({ auth, clientId, clientSecret, oidcEndpoint, userId }: AuthToProcess) {
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
    updateClientPublicKey: async (clientPubkey: string, signingKey: webcrypto.CryptoKeyPair) => {
      actual.updateClientPublicKey(clientPubkey, signingKey);
      log('DEBUG', `updateClientPublicKey: [${clientPubkey}] [${signingKey?.publicKey}]`);
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

type AnyClient = FileClient | NanoTDFClient | NanoTDFDatasetClient;

function addParams(client: AnyClient, argv: Partial<mainArgs>) {
  if (argv.attributes?.length) {
    client.dataAttributes = argv.attributes.split(',');
  }
  if (argv['users-with-access']?.length) {
    client.dissems = argv['users-with-access'].split(',');
  }
  log('SILLY', `Built encrypt params dissems: ${client.dissems}, attrs: ${client.dataAttributes}`);
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
        } else if (argv['log-level']) {
          const ll = argv['log-level'] as string;
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
        group: 'KAS Endpoint:',
        type: 'string',
        description: 'URL to non-default KAS instance (https://mykas.net)',
      })
      .option('oidcEndpoint', {
        demandOption: true,
        group: 'OIDC IdP Endpoint:',
        type: 'string',
        description: 'URL to non-default OIDC IdP (https://myidp.net)',
      })
      .option('auth', {
        group: 'Authentication:',
        type: 'string',
        description: 'Authentication string (<clientId>:<clientSecret>)',
      })
      .boolean('dpop')
      .implies('auth', '--no-clientId')
      .implies('auth', '--no-clientSecret')

      .option('clientId', {
        group: 'OIDC client credentials',
        alias: 'cid',
        type: 'string',
        description: 'IdP-issued Client ID',
      })
      .implies('clientId', 'clientSecret')

      .option('clientSecret', {
        group: 'OIDC client credentials',
        alias: 'cs',
        type: 'string',
        description: 'IdP-issued Client Secret',
      })
      .implies('clientSecret', 'clientId')

      .option('exchangeToken', {
        group: 'Token from trusted external IdP to exchange for Virtru auth',
        alias: 'et',
        type: 'string',
        description: 'Token issued by trusted external IdP',
      })
      .implies('exchangeToken', 'clientId')

      .option('containerType', {
        group: 'TDF Settings',
        alias: 't',
        choices: containerTypes,
        description: 'Container format',
        default: 'nano',
      })

      .option('userId', {
        group: 'TDF Settings',
        type: 'string',
        description: 'Owner email address',
      })

      // Examples
      .example('$0 --auth ClientID123:Cli3nt$ecret', '# OIDC client credentials')

      .example('$0 --clientId ClientID123 --clientSecret Cli3nt$ecret', '# OIDC client credentials')

      // POLICY
      .options({
        'users-with-access': {
          group: 'Policy Options',
          desc: 'Add users to the policy',
          type: 'string',
          default: '',
          validate: (users: string) => users.split(','),
        },
        attributes: {
          group: 'Policy Options',
          desc: 'Data attributes for the policy',
          type: 'string',
          default: '',
          validate: (attributes: string) => attributes.split(','),
        },
      })

      // COMMANDS
      .options({
        'log-level': {
          type: 'string',
          default: 'info',
          desc: 'Set logging level',
        },
        silent: {
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
          const authProvider = await processAuth(argv);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);

          const kasEndpoint = argv.kasEndpoint;
          if (argv.containerType === 'tdf3') {
            log('DEBUG', `TDF3 Client`);
            const client = new FileClient({ authProvider, kasEndpoint, dpopEnabled: argv.dpop });
            log('SILLY', `Initialized client ${JSON.stringify(client)}`);
            log('DEBUG', `About to decrypt [${argv.file}]`);
            const ct = await client.decrypt(argv.file as string);
            if (argv.output) {
              await ct.toFile(argv.output);
            } else {
              console.log(await ct.toString());
            }
          } else {
            const client =
              argv.containerType === 'nano'
                ? new NanoTDFClient(authProvider, kasEndpoint, undefined, argv.dpop)
                : new NanoTDFDatasetClient(authProvider, kasEndpoint, undefined, argv.dpop);
            const buffer = await processDataIn(argv.file as string);

            log('DEBUG', 'Decrypt data.');
            const plaintext = await client.decrypt(buffer);

            log('DEBUG', 'Handle output.');
            if (argv.output) {
              await writeFile(argv.output, Buffer.from(plaintext));
            } else {
              console.log(Buffer.from(plaintext).toString('utf8'));
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

          if ('tdf3' === argv.containerType) {
            log('DEBUG', `TDF3 Client`);
            const client = new FileClient({ authProvider, kasEndpoint, dpopEnabled: argv.dpop });
            log('SILLY', `Initialized client ${JSON.stringify(client)}`);
            addParams(client, argv);
            const ct = await client.encrypt(argv.file as string);
            if (!ct) {
              throw new CLIError('CRITICAL', 'Encrypt configuration error: No output?');
            }
            if (argv.output) {
              await ct.toFile(argv.output as string);
            } else {
              console.log(await ct.toString());
            }
          } else {
            const client =
              argv.containerType === 'nano'
                ? new NanoTDFClient(authProvider, kasEndpoint, undefined, argv.dpop)
                : new NanoTDFDatasetClient(authProvider, kasEndpoint, undefined, argv.dpop);
            log('SILLY', `Initialized client ${JSON.stringify(client)}`);

            addParams(client, argv);

            const buffer = await processDataIn(argv.file as string);
            const cyphertext = await client.encrypt(buffer);

            log('DEBUG', `Handle cyphertext output ${JSON.stringify(cyphertext)}`);
            if (argv.output) {
              await writeFile(argv.output, Buffer.from(cyphertext));
            } else {
              console.log(Buffer.from(cyphertext).toString('base64'));
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
          '@opentdf/cli': process.env.npm_package_version || 'UNRELEASED',
          '@opentdf/client': version,
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
