# Contributing to @crit-fumble/auth

Thanks for your interest in contributing. This is the published JWT mint/verify
and JWE cookie decrypt package that anchors the auth contract between the
Crit-Fumble apps. It's intentionally tiny — a single source of truth that both
sides import so the contract can't drift.

## Local dev setup

You need:

- **Node.js >= 22** (see `engines` in `package.json`)

```bash
# Clone, then:
npm install
```

No environment variables are required for the test suite; the byte-equiv tests
against `@auth/core/jwt` are pure crypto and run offline.

## Running tests

```bash
npm test           # Jest, including byte-equiv tests vs @auth/core/jwt
npm run typecheck  # tsc --noEmit
npm run build      # Emit dist/ via tsc
```

The `pre-push` Husky hook runs `npm test` and will block pushes on a red
suite. The `pre-commit` hook runs the secret scan, `npm run typecheck`, and
the unit tests. Don't bypass with `--no-verify`.

## Code conventions

This package is the **auth contract** between cfg-core-server and
cfg-core-browser. Be conservative:

- **No new runtime dependencies** without strong justification. The current
  surface (`jose`, `@auth/core`) is intentional and audited.
- **The `SessionPayload` shape is the contract.** Any change is a breaking
  change to both consuming apps — bump the major version and call it out
  loudly in the PR description.
- **Keep crypto strictly compatible** with `@auth/core/jwt`'s `encode()`
  output — the byte-equiv tests exist to catch regressions. If you must
  change the format, plan the migration in advance.
- **File size:** 800 lines hard maximum per file.
- **TypeScript strict mode** is on; keep it that way.
- **No `console.log` in published code.** This library runs in both Node and
  edge contexts and has no logger of its own.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/). Type
prefixes: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`, `build`,
`perf`, `style`, `revert`. Keep the subject lower-case and under ~100 chars.

A breaking change uses `!` after the type or a `BREAKING CHANGE:` footer:

```
feat!: change SessionPayload.subscriptionTier to required string

BREAKING CHANGE: cfg-core-server and cfg-core-browser must upgrade to ^2.0.0
```

## Submitting a pull request

1. **Fork** the repo and branch from `main`:
   `git checkout -b feat/your-change`
2. **Write tests.** Crypto changes especially need byte-equiv coverage — if
   you can't write a test that proves compatibility, the change probably
   isn't safe.
3. **Run locally** before pushing: `npm run typecheck && npm test`. Husky
   will run these on `pre-push` anyway.
4. **Commit** using Conventional Commits.
5. **Open a PR** against `main`. Explain the *why*, especially for any change
   to crypto, the `SessionPayload` shape, or the public API surface.
6. **Be patient and responsive** during review.

## Publishing

This is a published package on GitHub Packages. Publishing is gated to
maintainers — contributors do not need to think about it. Releases are cut by
bumping `version` in `package.json` on `main` and tagging.

## License

Contributions are accepted under [AGPL-3.0-only](LICENSE). By submitting a PR
you agree your contribution may be distributed under that license. See
[NOTICE](NOTICE) and [TRADEMARK.md](TRADEMARK.md) for attribution and
trademark policy.
