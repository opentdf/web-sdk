const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const repoRoot = path.resolve(__dirname, '..');
const joseRoot = path.dirname(require.resolve('jose/package.json'));
const sourceRoot = path.join(joseRoot, 'dist', 'webapi');
const destRoot = path.join(repoRoot, 'tdf3', 'src', 'crypto', 'jose', 'vendor');

const relativeImport = /\b(?:from|import)\s*["'](\.\.?\/[^"']+)["']/g;

// Re-exported from the jose package rather than copied, so the helpers throw the
// same classes as jose's public `errors`. Copying also breaks on jose >=6.2.11:
// its `super(...), this.x = ...` constructors get field initializers hoisted
// above super() when tsc downlevels class fields for our es2021 target.
const errorsModule = 'util/errors.js';

const header = (version) =>
  [
    '// @ts-nocheck',
    `// Generated from jose@${version}. Do not edit directly.`,
    '',
  ].join('\n');

const josePkg = JSON.parse(
  fs.readFileSync(path.join(joseRoot, 'package.json'), 'utf8')
);

const exportsOf = async (relPath) =>
  Object.keys(await import(pathToFileURL(path.join(sourceRoot, relPath)).href));

// jose moves its internal helpers between releases (validateCrit was in
// lib/validate_crit.js through 6.2.4, lib/options.js through 6.2.11, and
// lib/validate.js since), so look them up by export name. jose 6.0.x has
// them as the default exports of `legacyPath` instead.
async function locate(name, legacyPath) {
  const libDir = path.join(sourceRoot, 'lib');
  for (const file of fs.readdirSync(libDir).sort()) {
    const relPath = `lib/${file}`;
    if (
      file.endsWith('.js') &&
      fs.readFileSync(path.join(libDir, file), 'utf8').includes(name) &&
      (await exportsOf(relPath)).includes(name)
    ) {
      return { relPath, name };
    }
  }
  if (
    fs.existsSync(path.join(sourceRoot, legacyPath)) &&
    (await exportsOf(legacyPath)).includes('default')
  ) {
    return { relPath: legacyPath, name: 'default' };
  }
  throw new Error(`Cannot find ${name} in jose@${josePkg.version}`);
}

const reexport = ({ relPath, name }, as) =>
  `export { ${name === as ? as : `${name} as ${as}`} } from './${relPath}';`;

async function main() {
  const claims = await locate('validateClaimsSet', 'lib/jwt_claims_set.js');
  const crit = await locate('validateCrit', 'lib/validate_crit.js');

  // Stable names for tdf3/src/crypto/jose/*.ts. JWS_RECOGNIZED must match
  // validateCrit's convention (a Map before jose 6.2.12, a null-prototype
  // object since), so take jose's own when it exports one (6.2.5+).
  const index = [
    reexport(claims, 'validateClaimsSet'),
    reexport(crit, 'validateCrit'),
    (await exportsOf(crit.relPath)).includes('JWS_RECOGNIZED')
      ? reexport({ ...crit, name: 'JWS_RECOGNIZED' }, 'JWS_RECOGNIZED')
      : "export const JWS_RECOGNIZED = new Map([['b64', true]]);",
    '',
  ].join('\n');

  const { errors } = await import('jose');
  const sources = new Map([
    [
      errorsModule,
      [
        "import { errors } from 'jose';",
        `export const { ${Object.keys(errors).join(', ')} } = errors;`,
        '',
      ].join('\n'),
    ],
  ]);
  const pending = [claims.relPath, crit.relPath];
  while (pending.length) {
    const relPath = pending.pop();
    if (sources.has(relPath)) {
      continue;
    }
    const srcPath = path.join(sourceRoot, relPath);
    if (!fs.existsSync(srcPath)) {
      throw new Error(`Missing jose source file: ${srcPath}`);
    }
    const content = fs.readFileSync(srcPath, 'utf8');
    sources.set(relPath, content);
    for (const [, specifier] of content.matchAll(relativeImport)) {
      pending.push(path.posix.join(path.posix.dirname(relPath), specifier));
    }
  }
  sources.set('index.js', index);

  // Start clean so helpers dropped by newer jose releases don't linger.
  fs.rmSync(destRoot, { recursive: true, force: true });

  for (const [relPath, content] of sources) {
    const destPath = path.join(destRoot, relPath.replace(/\.js$/, '.ts'));
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.writeFileSync(destPath, header(josePkg.version) + content, 'utf8');
  }

  console.log(
    `Vendored ${sources.size} jose@${josePkg.version} modules into ${destRoot}`
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
