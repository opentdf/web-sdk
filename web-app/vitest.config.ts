import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    coverage: {
      provider: 'v8',
      // lcov for SonarCloud, text so a local run says something without
      // opening a file. sonar.sources already lists web-app/src, so without a
      // report every file here counts as uncovered new code.
      reporter: ['text', 'lcov'],
      // Report on all of src, not just the files a test happened to import.
      // Sonar treats absent files as uncovered anyway; listing them keeps the
      // local summary honest about how little of the demo app is tested.
      //
      // Expect near-zero numbers here and don't read anything into them. This
      // provider instruments the vitest Node process, and every test in this
      // package drives a real browser instead. The figures that matter come
      // from `npm run coverage:browser`, which reports the istanbul counters
      // the instrumented bundle accumulates in the page. This lane is kept
      // only so a future in-process unit test is measured at all.
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.d.ts', 'src/**/*.{test,spec}.{ts,tsx}'],
    },
  },
});
