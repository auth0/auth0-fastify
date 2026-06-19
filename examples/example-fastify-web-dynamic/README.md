# Fastify Dynamic Application Base URL Example

This example demonstrates how to use `auth0-fastify` with a **dynamic application
base URL** — where the URL used to build `redirect_uri` and
`post_logout_redirect_uri` is resolved per request instead of being hard-coded.

This is useful when a single application serves multiple hosts (for example
`brand-1.my-app.com` and `brand-2.my-app.com`) behind a proxy.

For a classic single-host setup, see the
[`example-fastify-web`](../example-fastify-web) example instead.

## How it works

Two pieces make this work:

1. The Fastify server is created with `trustProxy: true`, so Fastify derives
   `request.host` / `request.protocol` from the `X-Forwarded-Host` /
   `X-Forwarded-Proto` headers your proxy sets.
2. `appBaseUrl` is **not** a single hard-coded string. The SDK infers the base
   URL from those request accessors.

> [!IMPORTANT]
> When inferring the base URL, your proxy **must** sanitize and overwrite the
> `Host` and `X-Forwarded-Host` headers before they reach the app. Without a
> trusted proxy validating these headers, an attacker can influence the inferred
> base URL and cause malicious redirects.

## Install dependencies

```bash
npm install
```

## Configuration

Rename `.env.example` to `.env` and configure your Auth0 application:

```ts
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_CLIENT_ID=YOUR_AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_AUTH0_CLIENT_SECRET
AUTH0_SESSION_SECRET=YOUR_AUTH0_SESSION_SECRET
APP_BASE_URL=
```

Generate a session secret with `openssl`:

```shell
openssl rand -hex 64
```

`APP_BASE_URL` selects which mode the example runs in:

| `APP_BASE_URL` value | Mode | Behavior |
|----------------------|------|----------|
| unset / empty | **Dynamic** | Base URL inferred from every request, with no restriction. |
| a single URL | **Static** | A fixed base URL (same as the classic example). |
| comma-separated URLs | **Allow-list** | Base URL inferred per request, but the origin must match one of the listed values, otherwise the request is rejected with HTTP 500. |

Whichever inferred origins you use, register each one in Auth0 as an
**Allowed Callback URL** and **Allowed Logout URL**.

## Run

```bash
npm run start
```

The application has 3 routes:

- `/`: The home route. It shows the **resolved request origin** so you can see
  what the SDK infers for the current request.
- `/public`: A public route that can be accessed without authentication.
- `/private`: A private route that can only be accessed by authenticated users.

## Trying out dynamic inference locally

Because inference depends on the host/proto of each request, you need to send
different forwarded headers to see it change. A quick way is `curl` (note that
the SDK honors these headers only because the server enables `trustProxy`):

```bash
# Inferred origin = https://brand-1.example.com
curl -s -H "X-Forwarded-Host: brand-1.example.com" \
        -H "X-Forwarded-Proto: https" \
        http://localhost:3000/

# Inferred origin = https://brand-2.example.com
curl -s -H "X-Forwarded-Host: brand-2.example.com" \
        -H "X-Forwarded-Proto: https" \
        http://localhost:3000/
```

For a full login round-trip across hosts, put a real reverse proxy (nginx,
Caddy, etc.) in front of the app and have it set `X-Forwarded-Host` /
`X-Forwarded-Proto` per virtual host. Hostnames such as `*.localtest.me`
(which resolve to `127.0.0.1`) are handy for local multi-host testing.
