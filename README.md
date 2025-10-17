![Auth0-Fastify](assets/images/banner.png)
Auth0-Fastify Mono Repo, containing SDKs for implementing user authentication in Fastify applications.

![Release](https://img.shields.io/npm/v/@auth0/auth0-auth-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-auth-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/auth0/auth0-fastify)

📚 [Packages](#packages) - 💬 [Feedback](#feedback)

## Packages

- [`auth0-fastify`](./packages/auth0-fastify/README.md) - Authentication SDK for Fastify Applications on JavaScript runtimes.
- [`auth0-fastify-api`](./packages/auth0-fastify-api/README.md) - Authentication SDK for Fastify API's on JavaScript runtimes.

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