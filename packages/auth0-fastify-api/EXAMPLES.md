# Examples

- [Configuration](#configuration)
  - [Basic configuration](#basic-configuration)
  - [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
  - [Discovery cache configuration](#discovery-cache-configuration)
  - [Configuring a `customFetch` implementation](#configuring-a-customfetch-implementation)
- [Protecting API Routes](#protecting-api-routes)

## Configuration

### Basic configuration

Register the Auth0 fastify plugin with the Fastify instance.

```ts
import fastifyAuth0 from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});
```

The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. 
The `AUTH0_AUDIENCE` is the identifier of the API that is being called. You can find this in the API section of the Auth0 dashboard.


### Multiple Custom Domains (MCD)

When your API is served behind multiple custom domains, configure `domains`. Use the exact host values shown in the Auth0 Dashboard (e.g., `your-tenant.auth0.com` or `custom-domain.example.com`), without `https://` or any path; https and trailing slashes are normalized by `@auth0/auth0-api-js`. The plugin passes request headers and URL to `@auth0/auth0-api-js` for domain resolution.

> [!WARNING]  
> `DomainsResolver` often relies on request headers such as `Host` or `X-Forwarded-Host`. These headers can be spoofed by clients unless your Fastify instance is behind a trusted proxy and you have a clear trust boundary. Always validate/allowlist hosts and only honor forwarded headers from trusted infrastructure.

#### Static allowlist
```ts
import fastifyAuth0, { type Auth0FastifyApiOptions } from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

const options: Auth0FastifyApiOptions = {
  audience: '<AUTH0_AUDIENCE>',
  domains: [
    'your-tenant.auth0.com',
    'custom-domain.example.com',
  ],
};

fastify.register(fastifyAuth0, options);
```

#### Dynamic resolver
```ts
import fastifyAuth0, {
  type DomainsResolver,
  type DomainsResolverContext,
} from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

const domainsResolver: DomainsResolver = ({ url, headers }: DomainsResolverContext) => {
  const host =
    headers?.['x-forwarded-host'] ??
    headers?.['host'] ??
    (url ? new URL(url).host : undefined);

  if (host === 'api.my-app.com') {
    return ['custom-domain.example.com'];
  }

  return ['your-tenant.auth0.com'];
};

fastify.register(fastifyAuth0, {
  audience: '<AUTH0_AUDIENCE>',
  domain: '<AUTH0_DOMAIN>', // optional for verification-only, required for client flows
  domains: domainsResolver,
  algorithms: ['RS256'],
});
```

### Discovery cache configuration

You can control discovery/JWKS caching behavior by forwarding `discoveryCache` to the underlying ApiClient (TTL is in seconds). This cache is not MCD-specific; it applies to all verification flows.

- `ttl`: how long discovery metadata and JWKS fetchers are kept (seconds)
- `maxEntries`: max cached domains/JWKS entries before LRU eviction

Lower values increase network calls; higher values reduce network calls but increase memory use.

```ts
import fastifyAuth0 from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  discoveryCache: { ttl: 600, maxEntries: 100 },
});
```

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when registering the plugin:

```ts
import fastifyAuth0 from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  /* ... */
  customFetch: async (input, init) => {
    // Custom fetch implementation
  },
});
```

## The `ApiClient` instance

Once the plugin is registered, an instance of the Auth0 `ApiClient` is available via `fastify.auth0Client`. This instance can be used to call any of the methods available on the `ApiClient`, such as `verifyAccessToken()` and `getAccessTokenForConnection()`.

For the complete list of available methods, please refer to the [@auth0/auth0-api-js SDK documentation](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-api-js/README.md).

## Protecting API Routes

In order to protect an API route, you can use the SDK's `requireAuth()` method in a preHandler:

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
