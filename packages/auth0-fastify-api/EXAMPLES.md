# Examples

- [Configuration](#configuration)
  - [Basic Configuration](#basic-configuration)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
- [Discovery Cache Configuration](#discovery-cache-configuration)
- [Configuring a `customFetch` Implementation](#configuring-a-customfetch-implementation)
- [The `ApiClient` Instance](#the-apiclient-instance)
- [Protecting API Routes](#protecting-api-routes)

## Configuration

### Basic Configuration

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

### Configuring a `customFetch` Implementation

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

## Multiple Custom Domains (MCD)
Multiple Custom Domains (MCD) support enables a single API application to accept access tokens issued by multiple domains associated with the same Auth0 tenant, including the `canonical domain` and its `custom domains`.

This is commonly required in scenarios such as: 
- Multi-brand applications (B2C) where each brand uses a different custom domain but they all share the same API.
- A single API serves multiple frontend applications that use different custom domains.
- A gradual migration from the canonical domain to a custom domain, where both domains need to be supported during the transition period.

In these cases, your API must trust and validate tokens from multiple issuers instead of a single domain.

> [!IMPORTANT]  
> The `domains` configuration is intended for a single `Auth0` tenant and should include only that tenant’s canonical domain (for example, `your-tenant.auth0.com`) and its associated custom domains (for example, `brand1.auth.example.com`, `brand2.auth.example.com`). It is not designed to support domains from multiple `Auth0` tenants.

The SDK supports two approaches for configuring multiple allowed issuer domains:

### 1. Static Allowlist
Use a static allow-list when the set of trusted issuer domains is known in advance and remains the same for all requests.
This approach also works well for domain migration scenarios, where multiple domains (such as the canonical domain and one or more custom domains) need to be accepted during a transition period.
The SDK validates incoming tokens against a predefined list of allowed domains.

```ts
import fastifyAuth0, { type Auth0FastifyApiOptions } from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

const options: Auth0FastifyApiOptions = {
  audience: '<AUTH0_AUDIENCE>',
  domains: [
    'your-tenant.auth0.com',
    'brand1.auth.example.com',
    'brand2.auth.example.com',
  ],
};

fastify.register(fastifyAuth0, options);
```

### 2. Dynamic Domain Resolver
Use a dynamic resolver when the set of allowed issuer domains needs to be determined at runtime based on the incoming request.
The SDK provides a DomainsResolverContext containing request and token-derived information (url, headers, and unverifiedIss). You can use any combination of these inputs to determine the allowed issuer domains for the request.

In the following example, a single API application is accessed via two domains: 
- `api.brand1.com`
- `api.brand2.com`

Each domain is associated with a different Auth0 custom domain:
- `api.brand1.com` → `brand1.auth.example.com`
- `api.brand2.com` → `brand2.auth.example.com`

Using a dynamic resolver, you can determine the allowed issuer domains based on the incoming request’s hostname. This allows you to control which issuers the SDK should trust for each request.
```ts
import fastifyAuth0, {
  type DomainsResolver,
  type DomainsResolverContext,
} from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

const domainsResolver: DomainsResolver = ({ url }: DomainsResolverContext) => {
  const host = url ? new URL(url).hostname : undefined;
  if (host === 'api.brand1.com') {
    return ['brand1.auth.example.com'];
  }

  if (host === 'api.brand2.com') {
    return ['brand2.auth.example.com'];
  }

  // fallback to canonical domain
  return ['your-tenant.auth0.com'];
};

fastify.register(fastifyAuth0, {
  audience: '<AUTH0_AUDIENCE>',
  domain: '<AUTH0_DOMAIN>', // optional for verification-only, required for client flows
  domains: domainsResolver,
  algorithms: ['RS256'],
});
```

The resolver receives a `DomainsResolverContext` object with:
- `url`: the request URL, when available
- `headers`: the request headers
- `unverifiedIss`: the issuer read from the token before signature verification

It is the application's responsibility to decide how to use this information to return the allowed issuer domains. This allows the application to control which issuers the SDK can verify tokens from on a per-request basis. The resolver must return a non-empty array of domain strings.

> [!WARNING]
>
> When a domain resolver function is used, it may use request-derived values (such as `request.url`, `request.headers`, or `unverifiedIss`) to determine allowed issuer domains, which can be influenced by client input or intermediary infrastructure (for example, reverse proxies or load balancers).
>
> You must ensure that any inputs used in the resolver are **properly validated and come from trusted sources**. In particular, avoid relying directly on headers such as `Host` or `X-Forwarded-*` unless your proxy is correctly configured to sanitize and set them.
> Misconfigured proxies or improper validation can introduce serious security risks, including authentication bypass by allowing tokens from unintended issuers.
>

## Discovery Cache Configuration

You can control discovery and signing-key caching behavior with `discoveryCache`. This cache is not specific to MCD. It applies to all token verification flows.

By default, the SDK keeps two in-memory LRU caches with:
- `ttl: 600` seconds
- `maxEntries: 100`

The SDK maintains:
- a discovery metadata cache, keyed by normalized domain
- a signing-key fetcher cache, keyed by `jwks_uri`

The same `discoveryCache` settings apply to both caches.

Most applications can keep the defaults, but you may want to adjust them in the following cases:
- Increase `maxEntries` if one process may verify tokens for more than 100 distinct domains or JWKS URIs during the TTL window. This is most common in Multiple Custom Domains deployments that work with many custom domains.
- Decrease `maxEntries` if memory usage matters more than avoiding repeated discovery and signing-key setup.
- Increase `ttl` if the same domains are reused often and you want to reduce repeated discovery and signing-key setup after entries expire.
- Decrease `ttl` if you want the SDK to pick up metadata or signing-key changes sooner.
- Set `ttl` to `0` if you want to effectively disable cache reuse.

Rule of thumb:

Set `maxEntries` to cover the number of distinct domains or JWKS URIs a single process is expected to use during the TTL window, with some headroom.

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

## The `ApiClient` Instance

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
