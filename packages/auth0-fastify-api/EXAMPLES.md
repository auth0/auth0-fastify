# Examples

- [Configuration](#configuration)
  - [Basic Configuration](#basic-configuration)
  - [Configuring a `customFetch` Implementation](#configuring-a-customfetch-implementation)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
- [Discovery Cache Configuration](#discovery-cache-configuration)
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

The SDK supports two approaches for configuring multiple allowed issuer domains `Static Allowlist` and `Dynamic Domain Resolver`. 

### Static Allowlist
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
    'brand1.auth.example.com',
    'brand2.auth.example.com',
  ],
};

fastify.register(fastifyAuth0, options);
```

### Dynamic Domain Resolver
Use a dynamic resolver when the set of allowed issuer domains needs to be determined at runtime based on the incoming request.
The SDK provides a DomainsResolverContext containing request and token-derived information (url, headers, and unverifiedIss). You can use any combination of these inputs to determine the allowed issuer domains for the request.

In the following example, a single API application is accessed through two domains:

- `https://api.brand1.com/`
- `https://api.brand2.com/`

Each domain should only accept tokens issued by its corresponding Auth0 custom domains.

- `https://api.brand1.com/` should accept tokens issued by:
  - `brand1-en.auth.example.com`
  - `brand1-jp.auth.example.com`

- `https://api.brand2.com/` should accept tokens issued by:
  - `brand2-en.auth.example.com`
  - `brand2-jp.auth.example.com`

To enforce this behavior, you can configure a dynamic domain resolver that determines the allowed issuer domains based on the incoming request.
```ts
import fastifyAuth0, {
  type DomainsResolver,
  type DomainsResolverContext,
} from '@auth0/auth0-fastify-api';

const fastify = Fastify({
  logger: true,
});

const domainsResolver: DomainsResolver = (context: DomainsResolverContext) => {
  const host = context.url ? new URL(context.url).hostname : undefined;
  if (host === 'api.brand1.com') {
    return ['brand1-en.auth.example.com', 'brand1-jp.auth.example.com'];
  }

  if (host === 'api.brand2.com') {
    return ['brand2-en.auth.example.com', 'brand2-jp.auth.example.com'];
  }

  // fallback to default custom domains
  return ['default.auth.example.com'];
};

fastify.register(fastifyAuth0, {
  audience: '<AUTH0_AUDIENCE>',
  domain: '<AUTH0_DOMAIN>', // optional for verification-only, required for client flows
  domains: domainsResolver, // provide the resolver function instead of a static array
  algorithms: ['RS256'],
});
```

The resolver receives a `DomainsResolverContext` object with:
- `url`: the request URL, when available
- `headers`: the request headers
- `unverifiedIss`: the issuer read from the token before signature verification

It is the application's responsibility to decide how to use this information to return the allowed issuer domains. This allows the application to control which issuers the SDK can verify tokens from on a per-request basis. The resolver must return a non-empty array of domain strings.

### `domain` vs `domains` Configuration
This section explains the roles of `domain` and `domains`, and how the SDK determines which configuration is used for access token validation.
- When both `domain` and `domains` are configured, the SDK uses `domains` exclusively for access token verification.
- The `domain` option should be retained only if your application also performs client-side flows (for example, `getAccessTokenForConnection()` or `getTokenByExchangeProfile()`).
- When `domains` is specified, the SDK uses the provided issuer domains for discovery and token verification instead of `domain`.
- If `domains` is not configured, the SDK falls back to `domain` for discovery and token verification.

These values must be provided exactly as configured in the Auth0 Dashboard.

### Security Requirements
When configuring `domains` or a domain resolver for Multiple Custom Domains (MCD), you are responsible for ensuring that only trusted issuer domains are returned.

Mis-configuring the domain resolver is a critical security risk. It can cause the SDK to:
- accept access tokens from unintended issuers
- make discovery or JWKS requests to unintended domains

**Single Tenant Limitation:**
The `domains` configuration is intended only for multiple custom domains that belong to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single API.

**Fastify Request and Proxy Warning:**
If your resolver uses request-derived values such as `context.url`, `context.headers`, or `context.unverifiedIss`, do not trust those values directly. Use them only to map known and expected request values to a fixed allowlist of issuer domains that you control.

In particular:
- `context.url` and host-related request data may depend on your Fastify and proxy configuration
- if your application is behind a reverse proxy or load balancer, configure Fastify and your proxy so that host-related request information is trusted only when it comes from trusted infrastructure
- do not rely directly on `Host` or `X-Forwarded-*` unless your deployment is configured to sanitize and trust them correctly
- `context.unverifiedIss` comes from the token before signature verification and must not be trusted by itself

Misconfigured proxy handling or loose resolver logic can cause the SDK to trust unintended issuer domains.


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
