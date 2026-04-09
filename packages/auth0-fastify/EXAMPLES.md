# Examples

- [Configuration](#configuration)
  - [Basic configuration](#basic-configuration)
  - [Discovery Cache](#discovery-cache)
  - [Configuring the mounted routes](#configuring-the-mounted-routes)
- [The `ServerClient` instance](#the-serverclient-instance)
- [Protecting Routes](#protecting-routes)
- [Requesting an Access Token to call an API](#requesting-an-access-token-to-call-an-api)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)

## Configuration

### Basic configuration

Register the Auth0 fastify plugin with the Fastify instance.

```ts
import fastifyAuth0 from '@auth0/auth0-fastify';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  appBaseUrl: '<APP_BASE_URL>',
  sessionSecret: '<SESSION_SECRET>',
});
```

The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Regular Web Application`**.
The `SESSION_SECRET` is the key used to encrypt the session and transaction cookies. You can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

The `APP_BASE_URL` is the URL that your application is running on. When developing locally, this is most commonly `http://localhost:3000`.

### Discovery Cache

By default, the SDK caches discovery metadata and JWKS in memory using an `LRU` cache
with a `TTL` of `600` seconds and a maximum of `100` entries. To override these defaults:

In `@auth0/auth0-fastify`, `discoveryCache` is forwarded to the underlying `@auth0/auth0-server-js` client.
Cache reuse is scoped by resolved Auth0 domain (and mTLS mode), so each domain keeps its own discovery/JWKS entries.

Most `Fastify` applications can keep the defaults, but you may want to adjust `discoveryCache` in the following cases:
- Increase `maxEntries` if one `Fastify` process may handle more than `100` distinct Auth0 domains during the `TTL` window (common in larger MCD deployments).
- Increase `ttl` if domains are reused frequently and you want fewer repeated discovery/JWKS fetches after expiry.
- Decrease `ttl` if you want metadata/signing key changes to be picked up sooner.
- Decrease `maxEntries` if memory is tighter than network round-trip cost.
- Set `ttl` to `0` if you want to effectively disable discovery cache.

Rule of thumb:

- Set `maxEntries` close to the number of distinct Auth0 domains a single process is expected to serve during the `TTL` window, plus headroom.

```ts
fastify.register(fastifyAuth0, {
  // other options...
  discoveryCache: { ttl: 800, maxEntries: 200 },
});
```


### Configuring the mounted routes

By default, the SDK mounts the following routes:

- `auth/login`
- `auth/callback`
- `auth/logout`
- `auth/backchannel-logout`

The SDK can also be configured not to register these routes by setting the `mountRoutes` option to `false`:

```ts
import fastifyAuth0 from '@auth0/auth0-fastify';

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyAuth0, {
  /* ... */
  mountRoutes: false,
});
```

Additionally, by setting `mountConnectRoutes` to `true` (it's false by default) the SDK also can also mount 4 routes useful for account-linking:

1. `/auth/connect`: the route that the user will be redirected to to initiate account linking
2. `/auth/connect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs
3. `/auth/unconnect`: the route that the user will be redirected to to initiate account linking
4. `/auth/unconnect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs

> [!IMPORTANT]  
> When `mountRoutes` is set to `false`, setting `mountConnectRoutes` has no effect.

### Configuring a `customFetch` implementation

The SDK allows to override the fetch implementation, used for making HTTP requests, by providing a custom implementation when registering the plugin:

```ts
import fastifyAuth0 from '@auth0/auth0-fastify';

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

## The `ServerClient` instance

Once the plugin is registered, an instance of the Auth0 `ServerClient` is available via `fastify.auth0Client`. This instance can be used to call any of the methods available on the `ServerClient`, such as `getUser()`, `getSession()`, and `getAccessToken()`.

For the complete list of available methods, please refer to the [@auth0/auth0-server-js SDK documentation](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-server-js/README.md).

## Protecting Routes

In order to protect a Fastify route, you can use the SDK's `getSession()` method in a preHandler:

```ts
async function hasSessionPreHandler(request: FastifyRequest, reply: FastifyReply) {
  const session = await fastify.auth0Client!.getSession({ request, reply });

  if (!session) {
    reply.redirect('/auth/login');
  }
}

fastify.get(
  '/profile',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });

    return reply.viewAsync('profile.ejs', {
      name: user!.name,
    });
  }
);
```

> [!IMPORTANT]  
> The above is to protect server-side rendering routes by the means of a session, and not API routes using a bearer token. 

## Requesting an Access Token to call an API

If you need to call an API on behalf of the user, you want to specify the `audience` parameter when registering the plugin. This will make the SDK request an access token for the specified audience when the user logs in.

```ts
fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  audience: '<AUTH0_AUDIENCE>',
  appBaseUrl: '<APP_BASE_URL>',
  sessionSecret: '<SESSION_SECRET>',
});
```
The `AUTH0_AUDIENCE` is the identifier of the API you want to call. You can find this in the API section of the Auth0 dashboard.

Retrieving the token can be achieved by using `getAccessToken`:

```ts
const accessTokenResult = await fastify.auth0Client.getAccessToken({ request, reply });
console.log(accessTokenResult.accessToken);
```

## Multiple Custom Domains (MCD)

`Multiple Custom Domains` (MCD) lets you resolve the Auth0 domain per request while using a single Fastify plugin instance. This is useful when one application serves multiple customer domains (for example, `brand-1.my-app.com` and `brand-2.my-app.com`), each mapped to a different `Auth0` custom domain.

`MCD` is enabled by providing a `domain resolver function` instead of a static domain string, enabling you to dynamically define the `Auth0` custom domain at run-time.

Resolver mode is intended for the custom domains of a single `Auth0` tenant. It is not a supported way to connect multiple `Auth0` tenants to one application.

### Dynamic Domain Resolver

Provide a resolver function to select the domain at runtime. The resolver should return the `Auth0 Custom Domain` (for example, `brand-1.custom-domain.com`). Returning `null` or an empty value throws `InvalidConfigurationError`.
The resolver receives the same per-request `StoreOptions` object (`{ request, reply }` in `Fastify`) that the plugin passes internally to `auth0-server-js`.

#### Scenario 1: Host-based resolver with default fallback

```ts
import fastifyAuth0, { DomainResolver } from '@auth0/auth0-fastify';
import type { StoreOptions } from '@auth0/auth0-fastify';

const defaultAuth0Domain = 'auth.custom-domain.com';

const domainResolver: DomainResolver<StoreOptions> = async (storeOptions) => {
  const host = storeOptions?.request?.headers.host;
  const domains = {
    'brand-1.my-app.com': 'auth.custom-domain-1.com',
    'brand-2.my-app.com': 'auth.custom-domain-2.com',
  };

  return host ? domains[host] ?? defaultAuth0Domain : defaultAuth0Domain;
};

fastify.register(fastifyAuth0, {
  domain: domainResolver,
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  sessionSecret: '<SESSION_SECRET>',
  appBaseUrl: '<APP_BASE_URL>',
});
```

#### Scenario 2: Header-to-domain map (trusted app request context)

```ts
const headerValueToAuth0Domain: Record<string, string> = {
  workspace_a: 'workspace-a.custom-domain.com',
  workspace_b: 'workspace-b.custom-domain.com',
};

const domainResolver: DomainResolver<StoreOptions> = (storeOptions) => {
  // Example app header used for routing. This is app-specific context, not Auth0 tenant metadata.
  const routingKey = storeOptions?.request?.headers['x-tenant-id'];
  if (!routingKey) return 'auth.custom-domain.com';
  return headerValueToAuth0Domain[routingKey] ?? 'auth.custom-domain.com';
};
```


### Resolver Mode

Resolver mode means `domain` is configured as a resolver function. The plugin then passes per-request `storeOptions` into the underlying `ServerClient` so it can choose the correct `Auth0` domain for the current request.
- When you use the mounted routes, `{ request, reply }` is passed automatically.
- If you call `fastify.auth0Client` directly from your own routes, continue to pass `{ request, reply }` to those methods.
- If `appBaseUrl` is provided, that static value is used for callback and logout URLs.
- If `appBaseUrl` is omitted, the SDK infers the base URL from request headers.

If you omit `appBaseUrl`, make sure every inferred origin is registered in Auth0 as an `Allowed Callback URL` and `Allowed Logout URL`.



### Security Requirements

When configuring SDKs to resolve tenant custom domains via the domain resolver functions, you are responsible for ensuring that all resolved domains are trusted. Mis-configuring the domain resolver is a critical security risk that can lead to authentication bypass on the `relying party` (RP) or expose the application to `Server-Side Request Forgery` (SSRF).

**Single Tenant Limitation:** The domain resolvers are intended solely for multiple domains belonging to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single application.

**Secure Proxy Requirement:** When using `Multiple Custom Domains` (MCD), your application must be deployed behind a secure `Edge` or `Reverse Proxy` (e.g., `Cloudflare`, `Nginx`, or `AWS ALB`). The proxy must be configured to sanitize and overwrite `Host` and `X-Forwarded-Host` headers before they reach your application. Without a trusted proxy layer to validate these headers, an attacker can manipulate the domain resolution process. This can result in malicious redirects, where users are sent to `unauthorized` or `fraudulent` endpoints during the login and logout flows.

