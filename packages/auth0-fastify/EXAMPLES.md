# Examples

- [Configuration](#configuration)
  - [Basic configuration](#basic-configuration)
  - [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
  - [Discovery Cache](#discovery-cache)
  - [Configuring the mounted routes](#configuring-the-mounted-routes)
- [The `ServerClient` instance](#the-serverclient-instance)
- [Protecting Routes](#protecting-routes)
- [Requesting an Access Token to call an API](#requesting-an-access-token-to-call-an-api)

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

### Multiple Custom Domains (MCD)

For MCD, configure a `domain` resolver so the SDK can resolve the issuer per request. `appBaseUrl` can be static (recommended for subpath apps), or omitted to infer the base URL from the incoming request:

```ts
import { DomainResolver, DomainResolverContext } from '@auth0/auth0-fastify';

const domainResolver: DomainResolver = async ({ storeOptions }: DomainResolverContext) => {
  const host = storeOptions?.request?.headers.host;
  if (!host) return null;
  // Customer-provided mapping logic for resolving the correct Auth0 domain.
  return await lookupAuth0Domain(host);
};

fastify.register(fastifyAuth0, {
  domain: domainResolver,
  // Optional for MCD. If omitted, the base URL is inferred from the request host/proto.
  appBaseUrl: '<APP_BASE_URL>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  sessionSecret: '<SESSION_SECRET>',
});
```

If your resolver or inferred base URL depends on forwarded headers, ensure your proxy forwards them (e.g. `x-forwarded-host` and `x-forwarded-proto`).
When using a static `domain` (non-MCD), `appBaseUrl` is required.
If you omit `appBaseUrl`, make sure every inferred origin is registered in Auth0 as an Allowed Callback URL and Allowed Logout URL.

> [!IMPORTANT]
>
> When `appBaseUrl` is omitted in MCD, the SDK infers it from request headers.
> While convenient, this assumes that proxy headers are trusted.
>
> If your deployment does not strictly control the `Host` or `x-forwarded-*`
> headers, an attacker could influence redirect or logout URLs. In such cases,
> provide a static `appBaseUrl` or validate headers at the edge.

> [!IMPORTANT]  
> You will need to register the following URLs in your Auth0 Application via the [Auth0 Dashboard](https://manage.auth0.com):
>
> - Add `http://localhost:3000/auth/callback` to the list of **Allowed Callback URLs**
> - Add `http://localhost:3000` to the list of **Allowed Logout URLs**



### Discovery Cache

By default, the SDK caches discovery metadata and JWKS in memory using an LRU cache
with a TTL of `600` seconds and a maximum of `100` entries. To override these defaults:

```ts
fastify.register(fastifyAuth0, {
  // other options...
  discoveryCache: { ttl: 800, maxEntries: 200 },
});
```

When to configure discoveryCache:

- [Multiple Custom Domains](https://auth0.com/docs/customize/custom-domains/multiple-custom-domains).
- High-throughput services where you want fewer metadata fetches.
- Memory-constrained environments where you want a smaller cache.

To effectively disable discovery cache reuse, set `discoveryCache.ttl` to `0`.

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
