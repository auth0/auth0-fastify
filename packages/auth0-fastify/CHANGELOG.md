# Change Log

## [v1.1.0](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-v1.1.0) (2025-09-02)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-v1.0.2...auth0-fastify-v1.1.0)

**Added**
- feat: Allow to configure the routes for the mounted endpoints [#22](https://github.com/auth0/auth0-fastify/pull/22) ([frederikprijck](https://github.com/frederikprijck))

## [v1.0.2](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-v1.0.2) (2025-05-20)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-v1.0.1...auth0-fastify-v1.0.2)

**Fixed**
- fix: support older entry points [#13](https://github.com/auth0/auth0-fastify/pull/13) ([CarsonF](https://github.com/CarsonF))

## [v1.0.1](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-v1.0.1) (2025-03-27)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-v1.0.0...auth0-fastify-v1.0.1)

This version is the same as v1.0.0 in terms of features, but we have updated the README to fix a few broken links which requires a new patch release.

## [v1.0.0](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-v1.0.0) (2025-03-27)

The `@auth0/auth0-fastify` library allows for implementing user authentication in web applications on a JavaScript runtime.

In version 1.0.0, we have added the following features:

- We mount the following 4 routes automatically for you to use:
  - `GET /auth/login`
  - `GET /auth/callback`
  - `GET /auth/logout`
  - `POST /auth/backchannel-logout`
- Additionally, when `shouldMountConnectRoutes` is set to `true` explicitly, we also mount the following endpoints to help with Account Linking:
  - `GET /auth/connect`
  - `GET /auth/connect/callback`
  - `GET /auth/unconnect`
  - `GET /auth/unconnect/callback`
- The SDK uses a stateless token storage by default, but allows to log in to stateful storage if needed bu providing a `sessionStore` configuration option.
- In stateless storage mode, the SDK will use cookie-chunking to store the token in the browser's cookies.
- The entire underlying `ServerClient` (from `@auth0/auth0-server-js`) instance is exposed on `FastifyInstance` as `auth0Client` for advanced use-cases.

