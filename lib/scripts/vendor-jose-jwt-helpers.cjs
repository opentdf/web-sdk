const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const joseRoot = path.dirname(require.resolve('jose/package.json'));
const sourceRoot = path.join(joseRoot, 'dist', 'webapi');
const destRoot = path.join(repoRoot, 'tdf3', 'src', 'crypto', 'jose', 'vendor');

const files = [
  'lib/jwt_claims_set.js',
  'lib/validate_crit.js',
  'lib/secs.js',
  'lib/epoch.js',
  'lib/is_object.js',
  'lib/buffer_utils.js',
  'util/errors.js',
];

const header = (version) =>
  [
    '// @ts-nocheck',
    `// Generated from jose@${version}. Do not edit directly.`,
    '',
  ].join('\n');

const josePkg = JSON.parse(
  fs.readFileSync(path.join(joseRoot, 'package.json'), 'utf8')
);

for (const relPath of files) {
  const srcPath = path.join(sourceRoot, relPath);
  const destPath = path.join(destRoot, relPath.replace(/\.js$/, '.ts'));
  const destDir = path.dirname(destPath);

  if (!fs.existsSync(srcPath)) {
    throw new Error(`Missing jose source file: ${srcPath}`);
  }

  fs.mkdirSync(destDir, { recursive: true });
  const content = fs.readFileSync(srcPath, 'utf8');
  fs.writeFileSync(destPath, header(josePkg.version) + content, 'utf8');
}

console.log(`Vendored jose JWT helpers into ${destRoot}`);
