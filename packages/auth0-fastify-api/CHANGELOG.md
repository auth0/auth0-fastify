# Change Log

## [v1.3.0](https://github.com/auth0/auth0-fastify/tree/auth0-fastify-api-v1.3.0) (2026-05-18)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-api-v1.2.0...auth0-fastify-api-v1.3.0)

**Added**
- feat(auth0-fastify-api): Add DPoP support on auth0-fastify-api [\#60](https://github.com/auth0/auth0-fastify/pull/60) ([@nandan-bhat](https://github.com/nandan-bhat))
- feat(auth0-fastify-api): add on-behalf-of-token-exchange support on auth0-fastify-api [\#58](https://github.com/auth0/auth0-fastify/pull/58) ([@nandan-bhat](https://github.com/nandan-bhat))


## [v1.2.0](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-api-v1.2.0) (2026-04-09)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-api-v1.1.0...auth0-fastify-api-v1.2.0)

**Added**
- feat(auth0-fastify-api): Add MCD support [#45](https://github.com/auth0/auth0-fastify/pull/45) ([nandan-bhat](https://github.com/nandan-bhat))

## [v1.1.0](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-api-v1.1.0) (2025-10-02)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-api-v1.0.3...auth0-fastify-api-v1.1.0)

**Added**
- feat: decorate fastify instance with auth0Client[#32](https://github.com/auth0/auth0-fastify/pull/32) ([guabu](https://github.com/guabu))

## [v1.0.3](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-api-v1.0.3) (2025-08-14)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-api-v1.0.2...auth0-fastify-api-v1.0.3)

**Fixed**
- fix: correctly mark iss, sub, and aud claims as required [#21](https://github.com/auth0/auth0-fastify/pull/21) ([frederikprijck](https://github.com/frederikprijck))

## [v1.0.2](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-api-v1.0.2) (2025-05-19)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-api-v1.0.1...auth0-fastify-api-v1.0.2)

**Fixed**
- fix: support older entry points [#13](https://github.com/auth0/auth0-fastify/pull/13) ([CarsonF](https://github.com/CarsonF))

## [v1.0.1](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-api-v1.0.1) (2025-03-28)
[Full Changelog](https://github.com/auth0/auth0-fastify/compare/auth0-fastify-api-v1.0.0...auth0-fastify-api-v1.0.1)

This version is the same as v1.0.0 in terms of features, but we have updated the README to fix a few broken links which requires a new patch release.

## [v1.0.0](https://github.com/auth0/auth0-fastify/releases/tag/auth0-fastify-api-v1.0.0) (2025-03-27)

The `@auth0/auth0-fasdtify-api` library allows for securing Fastify API's running on a JavaScript runtime.

In version 1.0.0, we have added the following features:

- `requireAuth({ scopes })` method on `FastifyInstance` to protect endpoints.
- `getToken()` method on `FastifyRequest` to retrieve the token from the header.
- `user` property on `FastifyRequest` to expose the token claims.

