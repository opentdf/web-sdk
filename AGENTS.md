# Repository Guidelines

## Project Structure & Module Organization

- `lib/`: TypeScript SDK package published as `@opentdf/sdk` (`src/`, `tdf3/`, `tests/`).
- `cli/`: Node-based CLI published as `@opentdf/ctl` (entrypoint in `bin/`, sources in `src/`).
- `web-app/`: Vite + React sample browser app (`src/`, `public/`, `tests/`).
- `web-app/tests/`: Playwright test project (run independently from the app package).
- `scripts/`: repo tooling (e.g. platform codegen via `scripts/platform.sh`).
- `Makefile`: orchestrates “pack SDK → install into dependents” workflows across packages.

## Build, Test, and Development Commands

- `nvm use` (Node `22`, see `.nvmrc`).
- `make ci`: clean install + pack `lib/`, then install the packed SDK into `cli/` and `web-app/`.
- `make start`: builds everything, then runs `cd web-app && npm run dev`.
- `make lint` / `make test` / `make format` / `make license-check`: run the matching `npm run …` in `lib/`, `cli/`, and `web-app/`.
- Package-level (when iterating locally):
  - `cd lib && npm run build`
  - `cd web-app && npm run dev`
  - `cd cli && npm run build`

## Coding Style & Naming Conventions

- TypeScript + ESM modules across packages.
- Formatting: Prettier (see `.prettierrc.yaml`, `printWidth: 100`, `singleQuote: true`). Prefer `make format` or `npm run format`.
- Linting: ESLint (flat config in `eslint.config.mjs`). Fix-only changes should be isolated from feature changes.

## Testing Guidelines

- SDK: `cd lib && npm test` (runs multi-environment tests and enforces coverage thresholds).
- CLI: `cd cli && npm test` (Mocha).
- Web app: `cd web-app && npm test` (Vitest).
- Browser/e2e: `cd web-app/tests && npm test` (Playwright).

## Commit & Pull Request Guidelines

- Use Conventional Commits (common scopes: `sdk`, `cli`, `docs`, `ci`, `main`), e.g. `feat(sdk): add X` or `fix(cli): handle Y`.
- Include the relevant tracker key when available (e.g. `DSPX-####`, `SEC-####`).
- DCO is required: sign commits with `git commit -s` (see `CONTRIBUTING.md`).
- PRs should include: what/why, how to test, and screenshots for UI changes. Call out risk when touching auth/crypto or build/release flow.

## Agent-Specific Tips

- Use `rg` for fast text search; use `sg` (ast-grep) for structural refactors.
