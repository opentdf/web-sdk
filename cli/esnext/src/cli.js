import yargs from 'yargs';
import * as fs from 'fs';
import { hideBin } from 'yargs/helpers';
import { AuthProviders, NanoTDFClient } from '@opentdf/client';
import { log } from './logger.js';
async function processAuth({ auth, orgName, clientId, clientSecret, kasEndpoint, oidcEndpoint, }) {
    log('INFO', 'Processing auth params');
    if (auth) {
        log('DEBUG', 'Processing an auth string');
        const authParts = auth.split(':');
        if (authParts.length !== 3) {
            log('CRITICAL', 'Auth expects <orgName>:<clientId>:<clientSecret>');
            throw new Error();
        }
        [orgName, clientId, clientSecret] = authParts;
    }
    else if (!orgName || !clientId || !clientSecret) {
        log('CRITICAL', 'Auth expects orgName, clientId, and clientSecret');
        throw new Error();
    }
    log('INFO', `Building Virtru client for [${clientId}@${orgName}], via [${oidcEndpoint}]`);
    return new NanoTDFClient(await AuthProviders.clientSecretAuthProvider({
        organizationName: orgName,
        clientId,
        oidcOrigin: oidcEndpoint,
        exchange: 'client',
        clientSecret,
    }), kasEndpoint);
}
function processDataIn(file) {
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
export const handleArgs = (args) => {
    return (yargs(args)
        .middleware((argv) => {
        log.level = 'INFO';
        if (argv.silent) {
            log.level = 'CRITICAL';
        }
        else if (argv['log-level']) {
            const ll = argv['log-level'];
            log.level = ll.toUpperCase();
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
        .example('$0 --orgName MyOrg --clientId ClientID123 --clientSecret Cli3nt$ecret', '# OIDC client credentials')
        // POLICY
        .options({
        'users-with-access': {
            group: 'Policy Options',
            desc: 'Add users to the policy',
            type: 'string',
            default: '',
            validate: (users) => users.split(','),
        },
        attributes: {
            group: 'Policy Options',
            desc: 'Data attributes for the policy',
            type: 'string',
            default: '',
            validate: (attributes) => attributes.split(','),
        },
    })
        // COMMANDS
        .options({
        action: { choices: ['encrypt', 'decrypt'] },
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
        .command('decrypt [file]', 'Decrypt TDF to string', 
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    () => { }, async (argv) => {
        try {
            log('INFO', 'Running decrypt command');
            const client = await processAuth(argv);
            const buffer = processDataIn(argv.positional);
            log('INFO', 'Decrypt data.');
            const plaintext = await client.decrypt(buffer);
            log('INFO', 'Handle output.');
            console.log(Buffer.from(plaintext).toString('utf8'));
        }
        catch (e) {
            log(e);
        }
    })
        .command('encrypt [file]', 'Encrypt file or pipe to a TDF', 
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    (yargs) => {
        yargs.options({
            'out-html': {
                group: 'Encrypt Options',
                type: 'boolean',
                description: 'Output as TDF HTML (file size limit exists)',
            },
        });
    }, async (argv) => {
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
            const buffer = processDataIn(argv.positional);
            const cyphertext = await client.encrypt(buffer);
            log('INFO', 'Handle cyphertext output');
            console.log(Buffer.from(cyphertext).toString('base64'));
        }
        catch (e) {
            log(e);
        }
    })
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
        .parseAsync());
};
export const main = async (argsPromise) => {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xpLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2NsaS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEtBQUssTUFBTSxPQUFPLENBQUM7QUFDMUIsT0FBTyxLQUFLLEVBQUUsTUFBTSxJQUFJLENBQUM7QUFFekIsT0FBTyxFQUFFLE9BQU8sRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsYUFBYSxFQUFFLGFBQWEsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBRS9ELE9BQU8sRUFBUyxHQUFHLEVBQUUsTUFBTSxhQUFhLENBQUM7QUFXekMsS0FBSyxVQUFVLFdBQVcsQ0FBQyxFQUN6QixJQUFJLEVBQ0osT0FBTyxFQUNQLFFBQVEsRUFDUixZQUFZLEVBQ1osV0FBVyxFQUNYLFlBQVksR0FDRTtJQUNkLEdBQUcsQ0FBQyxNQUFNLEVBQUUsd0JBQXdCLENBQUMsQ0FBQztJQUN0QyxJQUFJLElBQUksRUFBRTtRQUNSLEdBQUcsQ0FBQyxPQUFPLEVBQUUsMkJBQTJCLENBQUMsQ0FBQztRQUMxQyxNQUFNLFNBQVMsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQ2xDLElBQUksU0FBUyxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7WUFDMUIsR0FBRyxDQUFDLFVBQVUsRUFBRSxrREFBa0QsQ0FBQyxDQUFDO1lBQ3BFLE1BQU0sSUFBSSxLQUFLLEVBQUUsQ0FBQztTQUNuQjtRQUVELENBQUMsT0FBTyxFQUFFLFFBQVEsRUFBRSxZQUFZLENBQUMsR0FBRyxTQUFTLENBQUM7S0FDL0M7U0FBTSxJQUFJLENBQUMsT0FBTyxJQUFJLENBQUMsUUFBUSxJQUFJLENBQUMsWUFBWSxFQUFFO1FBQ2pELEdBQUcsQ0FBQyxVQUFVLEVBQUUsa0RBQWtELENBQUMsQ0FBQztRQUNwRSxNQUFNLElBQUksS0FBSyxFQUFFLENBQUM7S0FDbkI7SUFFRCxHQUFHLENBQUMsTUFBTSxFQUFFLCtCQUEr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