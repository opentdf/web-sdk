import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin, type PluginOption } from 'vite';
import react from '@vitejs/plugin-react';
import istanbul from 'vite-plugin-istanbul';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const libRoot = path.join(repoRoot, 'lib');
const webAppEntry = fileURLToPath(new URL('index.html', import.meta.url));

// Set by `npm test` and by the roundtrip harness. Off by default: a normal
// `npm run dev` should use the packed SDK the same way a consumer would.
const coverage = !!process.env.COVERAGE;

function proxy(): Record<string, unknown> {
  const { VITE_PROXY } = process.env;
  if (VITE_PROXY) {
    console.log(`using VITE_PROXY [${VITE_PROXY}]`);
    return JSON.parse(VITE_PROXY);
  }
  console.log('using standard VITE_PROXY');
  return {
    '/kas': 'http://localhost:8080',
    '/auth': 'http://localhost:8888',
    '/api': {
      target: 'http://localhost:8080',
      changeOrigin: true,
      rewrite: (url: string) => url.replace(/^\/api/, ''),
    },
  };
}

// Mirrors the `exports` map in lib/package.json, pointing at TypeScript source
// instead of dist. Anything the app imports that is missing here fails to
// resolve, so the two lists have to be kept in step. Longest specifier first:
// Vite matches string aliases by prefix, in order.
const sdkSourceAliases = [
  { find: /^@opentdf\/sdk\/platform\/(.*)$/, replacement: path.join(libRoot, 'src/platform/$1') },
  { find: '@opentdf/sdk/singlecontainer', replacement: path.join(libRoot, 'tdf3/index.ts') },
  { find: '@opentdf/sdk/cryptoutils', replacement: path.join(libRoot, 'src/crypto/index.ts') },
  { find: '@opentdf/sdk/assertions', replacement: path.join(libRoot, 'tdf3/src/assertions.ts') },
  { find: '@opentdf/sdk/encodings', replacement: path.join(libRoot, 'src/encodings/index.ts') },
  { find: '@opentdf/sdk/platform', replacement: path.join(libRoot, 'src/platform.ts') },
  { find: '@opentdf/sdk', replacement: path.join(libRoot, 'src/index.ts') },
];

/**
 * The SDK compiles under NodeNext, so every one of its ~390 relative imports
 * names the emitted file (`./foo.js`) rather than the source (`./foo.ts`).
 * That is correct for tsc and meaningless to Vite, which would report every
 * one as missing. Rewrite `.js` to `.ts` for ids under lib/, and only when the
 * `.ts` actually exists so the vendored plain-JS files still resolve normally.
 */
function nodeNextSourceResolution(): Plugin {
  return {
    name: 'opentdf-nodenext-source-resolution',
    enforce: 'pre',
    resolveId(source, importer) {
      if (!source.endsWith('.js')) {
        return null;
      }
      const base = importer ? path.dirname(importer) : libRoot;
      const resolved = path.resolve(base, source);
      if (!resolved.startsWith(libRoot + path.sep)) {
        return null;
      }
      const asSource = `${resolved.slice(0, -'.js'.length)}.ts`;
      return existsSync(asSource) ? asSource : null;
    },
  };
}

/**
 * Node resolution walks up from the importer, so a bare specifier in
 * `lib/src/**` looks in `lib/node_modules` and then the repo root -- never in
 * `web-app/node_modules`. CI never installs lib/ in this job (it consumes the
 * packed tarball), so `@bufbuild/protobuf` and friends are unresolvable from
 * there. Resolve them as the app itself would instead, which is also the
 * dependency graph the app actually ships.
 */
function libDependencyResolution(): Plugin {
  return {
    name: 'opentdf-lib-dependency-resolution',
    enforce: 'pre',
    async resolveId(source, importer, options) {
      const bare = !/^[./]/.test(source) && !source.startsWith('node:') && !path.isAbsolute(source);
      if (!bare || !importer?.startsWith(libRoot + path.sep)) {
        return null;
      }
      return this.resolve(source, webAppEntry, { ...options, skipSelf: true });
    },
  };
}

function coveragePlugins(): PluginOption[] {
  if (!coverage) {
    return [];
  }
  return [
    nodeNextSourceResolution(),
    libDependencyResolution(),
    istanbul({
      // Relative to the repo root, so lib/ and web-app/ can both be named
      // without `..` segments that test-exclude handles poorly.
      cwd: repoRoot,
      include: ['web-app/src/**', 'lib/src/**', 'lib/tdf3/**'],
      exclude: ['**/*.d.ts', '**/*.test.*', '**/*.spec.*', 'lib/src/platform/**'],
      extension: ['.ts', '.tsx'],
      // Suite A runs against `vite preview`, which serves a production build.
      forceBuildInstrument: true,
      requireEnv: false,
    }),
  ];
}

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    rollupOptions: {
      shimMissingExports: true,
    },
  },
  plugins: [react(), ...coveragePlugins()],
  resolve: {
    alias: coverage ? sdkSourceAliases : [],
  },
  optimizeDeps: {
    // Pre-bundling would inline the SDK before the instrumenter sees it.
    exclude: coverage ? ['@opentdf/sdk'] : [],
  },
  server: {
    port: 65432,
    proxy: proxy(),
    fs: {
      // The dev server has to serve modules from ../lib in coverage mode.
      allow: coverage ? [repoRoot] : undefined,
    },
  },
});
