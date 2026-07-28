# Fastify Multiple Custom Domains (MCD) Example

This example demonstrates Multiple Custom Domains (MCD) support in `@auth0/auth0-fastify`.

A single Fastify app serves two distinct hostnames — `brand-a.localhost` and `brand-b.localhost` — on port 3000 using one plugin registration. Instead of a static `domain` string, the SDK is configured with a **domain resolver function** that maps each request's host to a different Auth0 custom domain of the **same Auth0 tenant**.

> MCD is intended for the custom domains of a single Auth0 tenant. It is not a supported way to connect multiple Auth0 tenants to one application.

## Install dependencies

```bash
npm install
```

## Add `/etc/hosts` entries

So that both hostnames resolve to your machine, add the following to `/etc/hosts`:

```text
127.0.0.1  brand-a.localhost
127.0.0.1  brand-b.localhost
```

## Configuration

Rename `.env.example` to `.env` and fill in your Auth0 credentials:

```ts
AUTH0_CLIENT_ID=YOUR_AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_AUTH0_CLIENT_SECRET
AUTH0_SESSION_SECRET=YOUR_AUTH0_SESSION_SECRET
AUTH0_DOMAIN=YOUR_DEFAULT_AUTH0_CUSTOM_DOMAIN
AUTH0_CUSTOM_DOMAIN_1=YOUR_FIRST_AUTH0_CUSTOM_DOMAIN
AUTH0_CUSTOM_DOMAIN_2=YOUR_SECOND_AUTH0_CUSTOM_DOMAIN
```

`AUTH0_CUSTOM_DOMAIN_1` and `AUTH0_CUSTOM_DOMAIN_2` are two [custom domains](https://auth0.com/docs/customize/custom-domains) configured on the same Auth0 tenant. `brand-a.localhost` resolves to the first, `brand-b.localhost` to the second, and any other host falls back to `AUTH0_DOMAIN`.

The `AUTH0_SESSION_SECRET` is the key used to encrypt the session cookie. You can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

> **No `APP_BASE_URL` is configured.** In resolver mode (`domain` is a function), `@auth0/auth0-fastify` infers the application base URL from each request's `Host` / `X-Forwarded-Host` and protocol headers, so callbacks, redirects, and logout use the correct origin per host. See [`src/index.ts`](./src/index.ts).

## Configure your Auth0 tenant

Because the app serves two origins, both must be registered in your Auth0 application settings:

- **Allowed Callback URLs:** `http://brand-a.localhost:3000/auth/callback, http://brand-b.localhost:3000/auth/callback`
- **Allowed Logout URLs:** `http://brand-a.localhost:3000, http://brand-b.localhost:3000`
- **Allowed Web Origins:** `http://brand-a.localhost:3000, http://brand-b.localhost:3000`

## Run the app

```bash
npm run start
```

The application has 3 routes:

- `/`: The home route, displaying a message depending on the authentication state.
- `/public`: A public route that can be accessed without authentication.
- `/private`: A private route that can only be accessed by authenticated users. Navigating here while unauthenticated redirects to Auth0 and back.

## Test the domain resolver

Open each origin in your browser and walk through login/logout on each:

- http://brand-a.localhost:3000
- http://brand-b.localhost:3000

When you log in from `brand-a.localhost`, the resolver maps that host to `AUTH0_CUSTOM_DOMAIN_1`, so the SDK authenticates against the first custom domain. The same flow on `brand-b.localhost` uses `AUTH0_CUSTOM_DOMAIN_2` — same configuration, correct Auth0 domain per request. The current host and the resolved Auth0 domain are displayed at the top of each page so you can confirm which is in use.

The SDK caches OIDC discovery metadata and JWKS **per resolved domain**, so serving many domains from one process stays efficient. See the `discoveryCache` option in `src/index.ts`.

## Security

You are responsible for ensuring every domain the resolver returns is a trusted custom domain of your Auth0 tenant. A resolver that returns an attacker-controlled value is a critical risk that can lead to authentication bypass or SSRF. When the resolver derives the domain from request headers (such as `Host`), deploy behind a trusted reverse proxy that sanitizes and overwrites `Host` / `X-Forwarded-Host` before they reach the app.
