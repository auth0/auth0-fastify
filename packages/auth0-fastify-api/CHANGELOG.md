# Change Log

## [v1.0.0](https://github.com/auth0/auth0-fastify/tree/auth0-fastify-api-v1.0.0) (2025-03-27)

The `@auth0/auth0-fasdtify-api` library allows for securing Fastify API's running on a JavaScript runtime.

In version 1.0.0, we have added the following features:

- `requireAuth({ scopes })` method on `FastifyInstance` to protect endpoints.
- `getToken()` method on `FastifyRequest` to retrieve the token from the header.
- `user` property on `FastifyRequest` to expose the token claims.
