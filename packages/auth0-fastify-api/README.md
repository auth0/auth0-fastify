The Auth0 Fastify-API SDK is a library for protecting API's in Fastify applications.

![Release](https://img.shields.io/npm/v/@auth0/auth0-fastify-api)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-fastify-api)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-fastify/blob/main/packages/auth0-fastify-api/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

```shell
npm i @auth0/auth0-fastify-api
```

This library requires Node.js 20 LTS and newer LTS versions.

### 3. Register the Auth0 Fastify plugin for APIs

Register the Auth0 fastify plugin for API's with the Fastify instance.

```ts
import fastifyAuth0Api from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});
```
The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an API. 
The `AUTH0_AUDIENCE` is the identifier of the API that is being called. You can find this in the API section of the Auth0 dashboard.

#### Protecting API Routes

In order to protect an API route, you can use the SDK's `requireAuth()` method in a preHandler:

```ts
fastify.register(() => {
  fastify.get(
    '/protected-api',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest, reply) => {
      return `Hello, ${request.user.sub}`;
    }
  );
});
```

The SDK exposes the claims, extracted from the token, as the `user` property on the `FastifyRequest` object.
In order to use a custom user type to represent custom claims, you can configure the `Token` type in a module augmentation:

```ts
declare module '@auth0/auth0-fastify-api' {
  interface Token {
    id: number;
    name: string;
    age: number;
  }
}
```

Doing so will change the user type on the `FastifyRequest` object automatically:

```ts
fastify.register(() => {
  fastify.get(
    '/protected-api',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest, reply) => {
      return `Hello, ${request.user.name}`;
    }
  );
});
```

> [!IMPORTANT]  
> The above is to protect API routes by the means of a bearer token, and not server-side rendering routes using a session. 


### DPoP (Demonstration of Proof-of-Possession)

DPoP binds access tokens to a specific client's key pair, preventing stolen tokens from being replayed by attackers. The SDK supports DPoP with three modes:

- **`allowed`** (default): accepts both Bearer and DPoP-bound tokens.
- **`required`**: only DPoP-bound tokens are accepted; Bearer tokens are rejected.
- **`disabled`**: DPoP is ignored; Bearer-only behavior.

```ts
import fastifyAuth0Api from '@auth0/auth0-fastify-api';

const fastify = Fastify({ logger: true });

fastify.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  dpop: { mode: 'required' },
});
```

When DPoP is enabled, clients send:
1. An `Authorization: DPoP <access_token>` header (instead of `Bearer`).
2. A `DPoP` header containing a proof JWT tied to the request method and URL.

The SDK automatically extracts the DPoP proof from the request, validates it against the access token's `cnf.jkt` claim, and verifies that the proof matches the current HTTP method and URL.

For the full configuration reference and error handling details, see the [DPoP section in EXAMPLES.md](https://github.com/auth0/auth0-fastify/blob/main/packages/auth0-fastify-api/EXAMPLES.md#dpop-demonstration-of-proof-of-possession).

### On-Behalf-Of Token Exchange

Use `fastify.auth0Client.getTokenOnBehalfOf()` when your Fastify API needs to call a downstream API on behalf of the same user, such as in an MCP server. The method exchanges the incoming access token for a new one scoped to the downstream API while preserving the user's identity.

`getTokenOnBehalfOf()` requires a confidential client. Register the plugin with `clientId` and `clientSecret` (or `clientAssertionSigningKey` for client assertion authentication).

```ts
import fastifyAuth0Api from '@auth0/auth0-fastify-api';

const fastify = Fastify({ logger: true });

fastify.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

fastify.register(() => {
  fastify.post(
    '/schedule-meeting',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest) => {
      // request.getToken() returns the raw JWT without the `Bearer ` prefix.
      const obo = await fastify.auth0Client!.getTokenOnBehalfOf(request.getToken()!, {
        audience: 'https://calendar-api.example.com',
        scope: 'calendar:read calendar:write',
      });

      const response = await fetch('https://calendar-api.example.com/meetings', {
        method: 'POST',
        headers: { authorization: `Bearer ${obo.accessToken}` },
        body: JSON.stringify(request.body),
      });

      return response.json();
    }
  );
});
```

For a full walkthrough including error handling, act claim inspection, and the downstream verifier pattern, see the [On-Behalf-Of Token Exchange](https://github.com/auth0/auth0-fastify/blob/main/packages/auth0-fastify-api/EXAMPLES.md#on-behalf-of-token-exchange) section in [EXAMPLES.md](https://github.com/auth0/auth0-fastify/blob/main/packages/auth0-fastify-api/EXAMPLES.md).


## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/auth0-fastify/blob/main/CONTRIBUTING.md)

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-fastify/blob/main/packages/auth0-fastify-api/LICENSE"> LICENSE</a> file for more info.
</p>
