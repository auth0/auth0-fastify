# Change Log

## [v1.0.0](https://github.com/auth0/auth0-fastify/tree/auth0-fastify-v1.0.0) (2025-03-27)

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

