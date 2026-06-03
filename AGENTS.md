# AGENTS.md

Onboarding for AI agents integrating Auth0 into a Fastify application using the
SDKs in this monorepo. For working *on* this repo (build/test/conventions), see
[CLAUDE.md](./CLAUDE.md).

## Pick the right package

| Your app is… | Use | Install |
|--------------|-----|---------|
| A server-rendered Fastify **web app** that logs users in and keeps a session | `@auth0/auth0-fastify` | `npm i @auth0/auth0-fastify` |
| A Fastify **API** that validates access tokens from callers | `@auth0/auth0-fastify-api` | `npm i @auth0/auth0-fastify-api` |
| Both (web app + separate API) | both packages | install both |

Requirements: Node.js 20 LTS+ and Fastify v5+.

## Web app — `@auth0/auth0-fastify`

Registers a Fastify plugin that mounts login, logout, and callback routes, and
stores an encrypted session cookie. Minimum configuration:

- `domain` — your Auth0 tenant domain.
- `clientId` / `clientSecret` — from your Auth0 Regular Web Application.
- `appBaseUrl` — the public base URL of your app.
- `sessionSecret` — secret used to encrypt the session cookie.

After registering, protect routes and read the authenticated user from the
session. Account linking, custom routes, interactive login without mounted
routes, backchannel logout, pushed authorization requests, and external session
stores are covered in
[packages/auth0-fastify/EXAMPLES.md](./packages/auth0-fastify/EXAMPLES.md).
Start from [packages/auth0-fastify/README.md](./packages/auth0-fastify/README.md).

## API — `@auth0/auth0-fastify-api`

Registers a plugin that validates incoming bearer access tokens against your
Auth0 tenant. Minimum configuration:

- `domain` — your Auth0 tenant domain.
- `audience` — the API identifier the token must be issued for.

Defaults to RS256 and rejects HS* algorithms. Enforce scopes per route, and use
DPoP or On-Behalf-Of token exchange where needed — see
[packages/auth0-fastify-api/EXAMPLES.md](./packages/auth0-fastify-api/EXAMPLES.md).
Start from
[packages/auth0-fastify-api/README.md](./packages/auth0-fastify-api/README.md).

## Guardrails when generating integration code

- **Secrets come from environment variables**, never hard-coded. All official
  examples read `clientSecret` / `sessionSecret` from env.
- **Behind a proxy/load balancer**, set `fastify.trustProxy` so the SDK derives
  the correct base URL from `x-forwarded-*` headers; do not trust those headers
  on a directly-exposed app.
- **Do not lower security defaults** (RS256, encrypted sessions).
- **Use Fastify v5 patterns** (await plugin registration); v4 syntax will not
  work.

## Try the examples first

- Web: [examples/example-fastify-web](./examples/example-fastify-web/README.md)
- API: [examples/example-fastify-api](./examples/example-fastify-api/README.md)

From the repo root: `npm install && npm run build`, then follow the example's
README.

## Official quickstarts

- Web: https://auth0.com/docs/quickstart/webapp/fastify
- API: https://auth0.com/docs/quickstart/backend/fastify
