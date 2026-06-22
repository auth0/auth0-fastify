![Auth0-Fastify](assets/images/banner.png)
Auth0-Fastify Mono Repo, containing SDKs for implementing user authentication in Fastify applications.

![Release](https://img.shields.io/npm/v/@auth0/auth0-auth-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-auth-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/auth0/auth0-fastify)

📚 [Packages](#packages) - 🔎 [Features](#features) - 💬 [Feedback](#feedback)

## Packages

Two SDKs — pick the one that matches your application:

- [`@auth0/auth0-fastify`](./packages/auth0-fastify/README.md) — for server-rendered **web apps** where users log in. Authenticates with an encrypted browser session cookie and handles login, logout, callback, and session management.
- [`@auth0/auth0-fastify-api`](./packages/auth0-fastify-api/README.md) — for **APIs** / resource servers consumed by SPAs, mobile, or services. Authenticates with an `Authorization: Bearer <access_token>` and authorizes by scopes and claims.

## Features

Jump straight to the capability you need.

### `@auth0/auth0-fastify` — Web applications

| Feature | What it does |
| --- | --- |
| [Quick start](./packages/auth0-fastify/README.md#getting-started) | Register the Auth0 plugin with `fastify.register` in a few lines |
| [Built-in routes](./packages/auth0-fastify/README.md#routes) | `/auth/login`, `/auth/logout`, `/auth/callback`, back-channel logout |
| [Custom login / logout / callback](./packages/auth0-fastify/README.md#3-adding-login-and-logout) | Roll your own routes instead of the mounted ones |
| [Configure mounted routes](./packages/auth0-fastify/EXAMPLES.md#configuring-the-mounted-routes) | Disable the built-in routes or add account-linking routes |
| [Protect a route with a session](./packages/auth0-fastify/README.md#4-protecting-routes) | Gate server-rendered pages behind a login session |
| [Get the current session / user](./packages/auth0-fastify/README.md#4-protecting-routes) | Read the authenticated user with `getUser()` / `getSession()` |
| [Call an API (`getAccessToken`)](./packages/auth0-fastify/README.md#requesting-an-access-token-to-call-an-api) | Get an access token to call APIs as the user |
| [Custom Token Exchange](./packages/auth0-fastify/EXAMPLES.md#login-using-custom-token-exchange) | Create a session from an external token without a browser login |
| [Multiple Custom Domains (MCD)](./packages/auth0-fastify/EXAMPLES.md#multiple-custom-domains-mcd) | Resolve the Auth0 domain per request |
| [Custom `fetch`](./packages/auth0-fastify/EXAMPLES.md#configuring-a-customfetch-implementation) | Swap in your own fetch (proxies, retries, instrumentation) |
| [Discovery cache](./packages/auth0-fastify/EXAMPLES.md#discovery-cache) | Control caching of OIDC discovery metadata and JWKS |

### `@auth0/auth0-fastify-api` — APIs

| Feature | What it does |
| --- | --- |
| [Quick start](./packages/auth0-fastify-api/README.md#getting-started) | Protect an API with `fastify.register` in a few lines |
| [Protect an API route (`requireAuth`)](./packages/auth0-fastify-api/README.md#protecting-api-routes) | Require a valid bearer access token in a preHandler |
| [Read token claims (`request.user`)](./packages/auth0-fastify-api/README.md#protecting-api-routes) | Access claims extracted from the verified token |
| [Custom token / user type](./packages/auth0-fastify-api/README.md#protecting-api-routes) | Type your custom claims via module augmentation |
| [DPoP (proof-of-possession)](./packages/auth0-fastify-api/EXAMPLES.md#dpop-demonstration-of-proof-of-possession) | Bind access tokens to a client key pair (RFC 9449) |
| [On-Behalf-Of Token Exchange](./packages/auth0-fastify-api/README.md#on-behalf-of-token-exchange) | Exchange the caller's token for a downstream API token |
| [Multiple Custom Domains (MCD)](./packages/auth0-fastify-api/EXAMPLES.md#multiple-custom-domains-mcd) | Accept tokens from multiple issuer domains of one tenant |
| [Custom `fetch`](./packages/auth0-fastify-api/EXAMPLES.md#configuring-a-customfetch-implementation) | Swap in your own fetch (proxies, retries, instrumentation) |
| [Discovery cache](./packages/auth0-fastify-api/EXAMPLES.md#discovery-cache-configuration) | Control caching of discovery metadata and signing keys |

## Running Examples

The following examples can be found in the examples directory:

- [Fastify Web App Example](./examples/example-fastify-web/README.md)
- [Fastify API Example](./examples/example-fastify-api/README.md)

Before running the examples, you need to install the dependencies for the monorepo and build all the packages.

1. Install depedencies

```bash
$ npm install
```

2. Build all packages

```bash
$ npm run build
```

3. Follow example instructions

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/auth0-fastify/blob/main/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-fastify/issues).

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-fastify/blob/main/packages/auth0-fastify/LICENSE"> LICENSE</a> file for more info.
</p>