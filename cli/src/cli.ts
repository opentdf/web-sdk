import yargs from 'yargs';
import { readFile, stat, writeFile } from 'fs/promises';
import { hideBin } from 'yargs/helpers';
import { AuthProviders, NanoTDFClient, version } from '@opentdf/client';

import { CLIError, Level, log } from './logger.js';

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
  log('DEBUG', 'Processing auth params');
  if (auth) {
    log('DEBUG', 'Processing an auth string');
    const authParts = auth.split(':');
    if (authParts.length !== 3) {
      throw new CLIError('CRITICAL', 'Auth expects <orgName>:<clientId>:<clientSecret>');
    }

    [orgName, clientId, clientSecret] = authParts;
  } else if (!orgName || !clientId || !clientSecret) {
    throw new CLIError(
      'CRITICAL',
      'Auth expects orgName, clientId, and clientSecret, or combined auth param'
    );
  }

  log('DEBUG', `Building Virtru client for [${clientId}@${orgName}], via [${oidcEndpoint}]`);
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

async function processDataIn(file: string) {
  if (!file) {
    throw new CLIError('CRITICAL', 'Must specify file or pipe');
  }
  const stats = await stat(file);
  if (!stats?.isFile()) {
    throw new CLIError('CRITICAL', `File does not exist [${file}]`);
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
          throw err;
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
      .option('output', {
        type: 'string',
        description: 'output file',
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
            log('DEBUG', 'Running decrypt command');
            const client = await processAuth(argv);
            const buffer = await processDataIn(argv.file as string);

            log('DEBUG', 'Decrypt data.');
            const plaintext = await client.decrypt(buffer);

            log('DEBUG', 'Handle output.');
            if (argv.output) {
              await writeFile(argv.output, Buffer.from(plaintext));
            } else {
              console.log(Buffer.from(plaintext).toString('utf8'));
            }
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
            log('DEBUG', 'Running encrypt command');
            const client = await processAuth(argv);

            log('SILLY', 'Build encrypt params');
            if (argv.attributes?.length) {
              client.dataAttributes = argv.attributes.split(',');
            }
            if (argv['users-with-access']?.length) {
              client.dissems = argv['users-with-access'].split(',');
            }
            log('DEBUG', 'Encrypting data');
            const buffer = await processDataIn(argv.file as string);
            const cyphertext = await client.encrypt(buffer);

            log('DEBUG', 'Handle cyphertext output');
            if (argv.output) {
              await writeFile(argv.output, Buffer.from(cyphertext));
            } else {
              console.log(Buffer.from(cyphertext).toString('base64'));
            }
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

      .version(
        'version',
        JSON.stringify({
          '@opentdf/cli': process.env.npm_package_version || 'UNRELEASED',
          '@opentdf/client': version,
        })
      )
      .alias('version', 'V')
      .parseAsync()
  );
};

export type mainArgs = ReturnType<typeof handleArgs>;
export const main = async (argsPromise: mainArgs) => {
  await argsPromise;
};

const a = handleArgs(hideBin(process.argv));
main(a)
  .then(() => {
    // Nothing;
  })
  .catch((err) => {
    console.error(err);
  });
