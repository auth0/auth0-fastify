# CLAUDE.md

Guidance for coding agents (Claude Code and others) working in this repository.

## What this is

A monorepo containing two published SDKs for adding Auth0 to Fastify (v5+)
applications on JavaScript runtimes. Both packages are TypeScript and require
Node.js 20 LTS or newer.

| Package | Path | Purpose |
|---------|------|---------|
| `@auth0/auth0-fastify` | `packages/auth0-fastify` | User authentication for server-rendered web apps: registers a Fastify plugin, mounts login/logout/callback routes, manages encrypted session cookies, protects routes, supports account linking. Built on `@auth0/auth0-server-js`. |
| `@auth0/auth0-fastify-api` | `packages/auth0-fastify-api` | API protection: validates bearer access tokens (RS256; HS* rejected), enforces audience/scopes, supports DPoP and On-Behalf-Of token exchange. Built on `@auth0/auth0-api-js`. |

Runnable examples live in `examples/example-fastify-web` and
`examples/example-fastify-api`.

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
- **Security defaults matter.** RS256 is the default for access-token
  validation and HS* algorithms are rejected; encrypted session cookies require
  a `sessionSecret`. Do not weaken these defaults.
- **Reverse-proxy awareness.** `inferAppBaseUrlFromRequest` in
  `packages/auth0-fastify/src/index.ts` reads `x-forwarded-host` /
  `x-forwarded-proto`. Only rely on those behind a trusted proxy
  (`fastify.trustProxy`).
- **Add tests** for behavior changes (`*.spec.ts` beside the source) and keep
  `npm run lint` clean before considering work done.
- **Match existing style.** Follow the patterns already in each package rather
  than introducing new abstractions.

## Where to look first

- New to the SDKs? Read `README.md` (root), then the package `README.md` and
  `EXAMPLES.md` for the package you are touching.
- Integrating, not modifying? See `AGENTS.md` for how to choose and wire up the
  right package.
