# Repository Guidelines

## Build, Test, and Development Commands

- `cli/` and `web-app/` consume the SDK as a packed tarball, not a workspace link. The `Makefile` orchestrates “pack SDK → install into dependents”:
  - `make ci`: clean install + pack `lib/`, then install the packed SDK into `cli/` and `web-app/`.
  - `make start`: builds everything, then runs `cd web-app && npm run dev`.
- `web-app/tests/` is a separate Playwright package (run independently: `cd web-app/tests && npm test`).
- `cd lib && npm test` runs multi-environment tests and enforces coverage thresholds.

## Coding Style & Naming Conventions

- Fix-only (lint/format) changes should be isolated from feature changes.

## Commit & Pull Request Guidelines

- Use Conventional Commits (common scopes: `sdk`, `cli`, `docs`, `ci`, `main`), e.g. `feat(sdk): add X` or `fix(cli): handle Y`.
- Include the relevant tracker key when available (e.g. `DSPX-####`, `SEC-####`).
- DCO is required: sign commits with `git commit -s` (see `CONTRIBUTING.md`).
- PRs should include: what/why, how to test, and screenshots for UI changes. Call out risk when touching auth/crypto or build/release flow.

## Agent-Specific Tips

- Use `rg` for fast text search; use `sg` (ast-grep) for structural refactors.
