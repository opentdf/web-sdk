import yargs from 'yargs';
import * as fs from 'fs';
import { webcrypto } from 'crypto';

import { hideBin } from 'yargs/helpers';
import { AuthProviders, NanoTDFClient } from '@opentdf/client';

import { Level, log } from './logger.js';

// Load global 'fetch' functions
import 'cross-fetch/dist/node-polyfill.js';

declare global {
  // eslint-disable-next-line no-var
  var crypto: typeof webcrypto;
}

async function loadCrypto() {
  if (!globalThis.crypto) {
    globalThis.crypto = webcrypto;
  }
}

type AuthToProcess = {
  auth?: string;
  orgName?: string;
  clientId?: string;
  clientSecret?: string;
  kasEndpoint: string;
  oidcEndpoint: string;
};

async function processAuth({
  auth,
  orgName,
  clientId,
  clientSecret,
  kasEndpoint,
  oidcEndpoint,
}: AuthToProcess) {
  log('INFO', 'Processing auth params');
  if (auth) {
    log('DEBUG', 'Processing an auth string');
    const authParts = auth.split(':');
    if (authParts.length !== 3) {
      log('CRITICAL', 'Auth expects <orgName>:<clientId>:<clientSecret>');
      throw new Error();
    }

    [orgName, clientId, clientSecret] = authParts;
  } else if (!orgName || !clientId || !clientSecret) {
    log('CRITICAL', 'Auth expects orgName, clientId, and clientSecret');
    throw new Error();
  }

  log('INFO', `Building Virtru client for [${clientId}@${orgName}], via [${oidcEndpoint}]`);
  return new NanoTDFClient(
    await AuthProviders.clientSecretAuthProvider({
      organizationName: orgName,
      clientId,
      oidcOrigin: oidcEndpoint,
      exchange: 'client',
      clientSecret,
    }),
    kasEndpoint
  );
}

function processDataIn(file: string) {
  if (!file) {
    log('CRITICAL', 'Must specify file or pipe');
    throw new Error();
  }
  log('DEBUG', 'Checking if file exists.');
  const stats = fs.statSync(file);
  if (!stats?.isFile()) {
    log('CRITICAL', `File does not exist [${file}]`);
    throw new Error();
  }
  log('DEBUG', `Found file [${file}]`);
  log('INFO', 'Using file input');
  return fs.readFileSync(file);
}

export const handleArgs = (args: string[]) => {
  return (
    yargs(args)
      .middleware((argv) => {
        log.level = 'INFO';
        if (argv.silent) {
          log.level = 'CRITICAL';
        } else if (argv['log-level']) {
          const ll = argv['log-level'] as string;
          log.level = ll.toUpperCase() as Level;
        }
        return argv;
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
        description: 'Authentication string (<orgName>:<clientId>:<clientSecret>)',
      })
      .implies('auth', '--no-org')
      .implies('auth', '--no-clientId')
      .implies('auth', '--no-clientSecret')

      .option('orgName', {
        group: 'OIDC client credentials',
        alias: 'org',
        type: 'string',
        description: 'OIDC realm/org',
      })
      .implies('orgName', 'clientId')
      .implies('orgName', 'clientSecret')

      .option('clientId', {
        group: 'OIDC client credentials',
        alias: 'cid',
        type: 'string',
        description: 'IdP-issued Client ID',
      })
      .implies('clientId', 'clientSecret')
      .implies('clientId', 'orgName')

      .option('clientSecret', {
        group: 'OIDC client credentials',
        alias: 'cs',
        type: 'string',
        description: 'IdP-issued Client Secret',
      })
      .implies('clientSecret', 'clientId')
      .implies('clientSecret', 'orgName')

      .option('exchangeToken', {
        group: 'Token from trusted external IdP to exchange for Virtru auth',
        alias: 'et',
        type: 'string',
        description: 'Token issued by trusted external IdP',
      })
      .implies('exchangeToken', 'clientId')
      .implies('exchangeToken', 'orgName')

      // Examples
      .example('$0 --auth MyOrg:ClientID123:Cli3nt$ecret', '# OIDC client credentials')

      .example(
        '$0 --orgName MyOrg --clientId ClientID123 --clientSecret Cli3nt$ecret',
        '# OIDC client credentials'
      )

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
      .command(
        'decrypt [file]',
        'Decrypt TDF to string',
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        (yargs) => {
          yargs.positional('file', {
            describe: 'path to plain text file',
            type: 'string',
          });
        },
        async (argv) => {
          try {
            log('INFO', 'Running decrypt command');
            const client = await processAuth(argv);
            console.log(argv.positional);
            const buffer = processDataIn(argv.file as string);

            log('INFO', 'Decrypt data.');
            const plaintext = await client.decrypt(buffer);

            log('INFO', 'Handle output.');
            console.log(Buffer.from(plaintext).toString('utf8'));
          } catch (e) {
            log(e);
          }
        }
      )
      .command(
        'encrypt [file]',
        'Encrypt file or pipe to a TDF',
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        (yargs) => {
          yargs.positional('file', {
            describe: 'path to plain text file',
            type: 'string',
          });
        },
        async (argv) => {
          try {
            log('INFO', 'Running encrypt command');
            const client = await processAuth(argv);

            log('SILLY', 'Build encrypt params');
            if (argv.attributes?.length) {
              client.dataAttributes = argv.attributes.split(',');
            }
            if (argv['users-with-access']?.length) {
              client.dissems = argv['users-with-access'].split(',');
            }
            log('INFO', 'Encrypting data');
            console.log(argv);
            const buffer = processDataIn(argv.file as string);
            const cyphertext = await client.encrypt(buffer);

            log('INFO', 'Handle cyphertext output');
            console.log(Buffer.from(cyphertext).toString('base64'));
          } catch (e) {
            log(e);
          }
        }
      )
      .usage('openTDF CLI\n\nUsage: $0 [options]')
      .alias('help', 'h')
      .showHelpOnFail(false, 'Something went wrong. Run with --help')
      .demandCommand()
      .recommendCommands()
      .help('help')
      .options({
        env: {
          desc: 'Set the environment',
        },
      })

      .version('version', process.env.npm_package_version || 'UNRELEASED')
      .alias('version', 'V')
      .parseAsync()
  );
};

export type mainArgs = ReturnType<typeof handleArgs>;
export const main = async (argsPromise: mainArgs) => {
  await loadCrypto();
  const args = await argsPromise;
  console.log(`"action" was [${args.action}].`);
};

const a = handleArgs(hideBin(process.argv));
main(a)
  .then((text) => {
    console.log(text);
  })
  .catch((err) => {
    console.error(err);
  });
