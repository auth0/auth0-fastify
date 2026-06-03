# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

A monorepo containing two published TypeScript SDKs for adding Auth0 to Fastify
(v5+) applications. Requires Node.js 20 LTS or newer.

| Package | Path | What it is | Built on |
|---------|------|-----------|----------|
| `@auth0/auth0-fastify` | `packages/auth0-fastify` | Web app authentication SDK | `@auth0/auth0-server-js` |
| `@auth0/auth0-fastify-api` | `packages/auth0-fastify-api` | API protection SDK | `@auth0/auth0-api-js` |

For what each SDK does and how to use it, see the package `README.md` and
`EXAMPLES.md`.

## Layout

```
packages/auth0-fastify/        # web auth SDK (source in src/, tests are *.spec.ts)
packages/auth0-fastify-api/    # API protection SDK
examples/                      # runnable example apps (npm workspaces)
.github/workflows/             # CI: build, test (Node 20 & 22), Snyk SCA
```

## Build, test, lint

This is an npm workspaces monorepo orchestrated with Turborepo. Run from the
repo root:

```bash
npm install            # install all workspace deps
npm run build          # turbo run build (all packages)
npm run test           # turbo run test (all packages)
npm run lint           # turbo run lint
npm run docs           # generate TypeDoc
```

Target a single package with npm workspaces:

```bash
npm run build -w @auth0/auth0-fastify
npm run test:ci -w @auth0/auth0-fastify-api
```

Tests are colocated with source as `*.spec.ts`. CI runs on Node 20 and 22, so
keep changes compatible with both.

## Conventions

- **TypeScript, Fastify v5+, Node 20+.** Do not introduce Fastify v4 patterns
  (e.g. non-awaited plugin registration) — the SDKs require v5.
- **Keep packages independent.** A change to the web package must not require a
  change to the API package unless intentional; they ship separately and are
  versioned independently.
- **Don't weaken security defaults when editing.** Token validation defaults to
  RS256 and rejects HS* algorithms; session cookies are encrypted and require a
  `sessionSecret`. Preserve these when modifying the relevant code.
- **Add tests** for behavior changes (`*.spec.ts` beside the source) and keep
  `npm run lint` clean before considering work done.
- **Conventional commits.** Match the existing history (`feat(scope):`,
  `fix(scope):`, `chore(scope):`).
- **Match existing style.** Follow the patterns already in each package rather
  than introducing new abstractions.

## Where to look first

Read `README.md` (root), then the package `README.md` and `EXAMPLES.md` for the
package you are touching. `llms.txt` is a structured index of the repo's docs.
