# Examples

- [Configuration](#configuration)
  - [Basic Configuration](#basic-configuration)
  - [Configuring a `customFetch` Implementation](#configuring-a-customfetch-implementation)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
- [Discovery Cache Configuration](#discovery-cache-configuration)
- [DPoP (Demonstration of Proof-of-Possession)](#dpop-demonstration-of-proof-of-possession)
- [The `ApiClient` Instance](#the-apiclient-instance)
- [On-Behalf-Of Token Exchange](#on-behalf-of-token-exchange)
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
The SDK provides a `DomainsResolverContext` containing request and token-derived information (`url`, `headers`, and `unverifiedIss`). You can use any combination of these inputs to determine the allowed issuer domains for the request.

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

Prefer domain values exactly as shown in the Auth0 Dashboard (for example, `example.auth0.com`).

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
- `context.url` is derived from Fastify's `request.host` and `request.protocol`, so configure Fastify `trustProxy` correctly if your application is behind a reverse proxy or load balancer
- if your application is behind a reverse proxy or load balancer, configure Fastify and your proxy so that host-related request information is trusted only when it comes from trusted infrastructure
- if you inspect `context.headers` directly, do not rely on raw `Host` or `X-Forwarded-*` unless your deployment is configured to sanitize and trust them correctly
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

## DPoP (Demonstration of Proof-of-Possession)

[DPoP (RFC 9449)](https://datatracker.ietf.org/doc/html/rfc9449) is a mechanism that binds access tokens to a specific client key pair. Even if a DPoP-bound token is stolen, it cannot be used without the corresponding private key, significantly reducing the impact of token theft.

### How DPoP Works

1. The client generates an asymmetric key pair (ES256).
2. When requesting a token from Auth0, the client presents a DPoP proof JWT signed with its private key.
3. Auth0 issues an access token bound to that key via the `cnf.jkt` (confirmation JSON Key Thumbprint) claim.
4. When calling your API, the client sends:
   - `Authorization: DPoP <access_token>` (not `Bearer`)
   - `DPoP: <proof_jwt>` header containing a proof JWT tied to the HTTP method and URL

The SDK automatically extracts the DPoP proof, validates the binding, and verifies the proof against the request.

### Configuration

Configure DPoP behavior using the `dpop` option:

```ts
import fastifyAuth0Api, { type DPoPOptions } from '@auth0/auth0-fastify-api';

const fastify = Fastify({ logger: true });

fastify.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  dpop: {
    mode: 'required',    // 'allowed' | 'required' | 'disabled'
    iatOffset: 300,      // max age of proof in seconds (default: 300)
    iatLeeway: 30,       // future clock skew tolerance in seconds (default: 30)
  },
});
```

### DPoP Modes

| Mode | Behavior |
|------|----------|
| `allowed` (default) | Accepts both Bearer tokens and DPoP-bound tokens. When a DPoP proof is present or the token contains a `cnf.jkt` claim, DPoP validation is performed. |
| `required` | Only DPoP-bound tokens are accepted. Bearer tokens are rejected with a `DPoP` challenge in `WWW-Authenticate`. |
| `disabled` | DPoP is completely ignored. Only Bearer tokens are accepted. |

### Route Protection with DPoP

No changes are needed in your route handlers. The `requireAuth()` preHandler automatically handles DPoP validation:

```ts
fastify.register(() => {
  fastify.get(
    '/protected-resource',
    {
      preHandler: fastify.requireAuth({ scopes: 'read:data' }),
    },
    async (request: FastifyRequest) => {
      // request.user contains the verified token claims
      // Works identically for both Bearer and DPoP-bound tokens
      return { data: request.user.sub };
    }
  );
});
```

### Error Handling

DPoP introduces additional error types. All are exported from `@auth0/auth0-fastify-api`:

```ts
import fastifyAuth0Api, {
  InvalidDpopProofError,
  InvalidRequestError,
  VerifyAccessTokenError,
} from '@auth0/auth0-fastify-api';
```

| Error Class | HTTP Status | When |
|-------------|-------------|------|
| `InvalidDpopProofError` | 400 | The DPoP proof JWT fails validation (wrong method, URL, expired, bad signature, etc.) |
| `InvalidRequestError` | 400 | Missing DPoP proof when required, invalid authentication scheme, or scheme mismatch |
| `VerifyAccessTokenError` | 401 | Token verification fails (expired, bad signature, missing `cnf.jkt` for DPoP scheme, etc.) |

The SDK returns RFC-compliant `WWW-Authenticate` response headers with appropriate challenges:

- **Mode `allowed`**: `Bearer realm="api", ..., DPoP algs="ES256"`
- **Mode `required`**: `DPoP algs="ES256", error="...", error_description="..."`
- **Mode `disabled`**: `Bearer realm="api", error="...", error_description="..."`

### DPoP with Multiple Custom Domains

DPoP works seamlessly with the Multiple Custom Domains (MCD) feature. The `httpUrl` used for DPoP proof validation is derived from the same request URL used for domain resolution:

```ts
fastify.register(fastifyAuth0Api, {
  audience: '<AUTH0_AUDIENCE>',
  domains: ['brand1.auth.example.com', 'brand2.auth.example.com'],
  dpop: { mode: 'required' },
});
```

### Timing Configuration

The `iatOffset` and `iatLeeway` options control how the SDK validates the DPoP proof's `iat` (issued-at) claim:

- **`iatOffset`** (default: 300 seconds): Maximum age of a DPoP proof. A proof issued more than `iatOffset` seconds ago is rejected.
- **`iatLeeway`** (default: 30 seconds): Allowed future clock skew. A proof with `iat` up to `iatLeeway` seconds in the future is accepted.

The acceptable `iat` window is: `[now - iatOffset, now + iatLeeway]`.

```ts
fastify.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
  dpop: {
    mode: 'allowed',
    iatOffset: 600,  // accept proofs up to 10 minutes old
    iatLeeway: 60,   // allow up to 60 seconds of future clock skew
  },
});
```

> [!IMPORTANT]
> The only supported DPoP proof algorithm is **ES256**. The SDK rejects proofs signed with other algorithms.

> [!NOTE]
> When `dpop.mode` is not set, it defaults to `'allowed'`, meaning your existing Bearer-token clients continue to work without any changes while DPoP-capable clients can opt in.

## The `ApiClient` Instance

Once the plugin is registered, an instance of the Auth0 `ApiClient` is available via `fastify.auth0Client`. This instance can be used to call any of the methods available on the `ApiClient`, such as `verifyAccessToken()` and `getAccessTokenForConnection()`.

For the complete list of available methods, please refer to the [@auth0/auth0-api-js SDK documentation](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-api-js/README.md).

## On-Behalf-Of Token Exchange

Use `fastify.auth0Client.getTokenOnBehalfOf()` when your Fastify API receives an Auth0 access token for itself and needs to exchange it for another Auth0 access token targeting a downstream API, while preserving the same user identity. This is especially useful for MCP servers and other intermediary APIs that need to call downstream APIs on behalf of the user.

The flow has three steps:

1. **Verify** the incoming access token so your API rejects invalid or mis-targeted tokens before exchanging.
2. **Exchange** the verified token for a new access token scoped to the downstream API.
3. **Call** the downstream API using the exchanged token.

`getTokenOnBehalfOf()` requires a confidential client. The plugin must be registered with `clientId` and at least one of `clientSecret` or `clientAssertionSigningKey`. Calling it without client credentials throws `MissingClientAuthError`.

### Plugin Registration

When using OBO, configure the plugin with credentials in addition to `domain` and `audience`:

```ts
import fastifyAuth0Api from '@auth0/auth0-fastify-api';

const fastify = Fastify({ logger: true });

fastify.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',          // your MCP server's Auth0 tenant domain
  audience: '<AUTH0_AUDIENCE>',      // your MCP server's API audience
  clientId: '<AUTH0_CLIENT_ID>',     // required for OBO
  clientSecret: '<AUTH0_CLIENT_SECRET>', // required for OBO (or use clientAssertionSigningKey)
});
```

### Performing the Exchange

Inside a route handler, verify the incoming token first, then exchange it for a downstream audience:

```ts
import type { FastifyRequest, FastifyReply } from 'fastify';
import { getCurrentActor, getDelegationChain } from '@auth0/auth0-fastify-api';

fastify.register(() => {
  fastify.post(
    '/schedule-meeting',
    {
      preHandler: fastify.requireAuth(),
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      // request.user is already verified by requireAuth()
      const incomingAccessToken = request.getToken()!;

      // Exchange the verified token for a token scoped to the downstream Calendar API.
      // Pass the raw token — do not include the `Bearer ` prefix.
      const obo = await fastify.auth0Client!.getTokenOnBehalfOf(incomingAccessToken, {
        audience: 'https://calendar-api.example.com',
        scope: 'calendar:read calendar:write',
      });

      // Call the downstream API with the exchanged token.
      const response = await fetch('https://calendar-api.example.com/meetings', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${obo.accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(request.body),
      });

      if (!response.ok) {
        throw new Error(`Calendar API request failed with ${response.status}`);
      }

      return { user: request.user.sub, meeting: await response.json() };
    }
  );
});
```

> [!TIP]
> **Production notes:**
> - `requireAuth()` in the `preHandler` verifies the incoming token before your handler runs. Always protect routes with `requireAuth()` before calling `getTokenOnBehalfOf()`.
> - `request.getToken()` returns the raw JWT from the `Authorization` header, without the `Bearer ` prefix. Pass this directly to `getTokenOnBehalfOf()`.
> - The downstream `audience` must match an API identifier configured in your Auth0 tenant, and your client must be authorized to access it.
> - `getTokenOnBehalfOf()` only returns access-token-oriented fields. It does not expose `idToken` or `refreshToken`.
> - OBO requires a **confidential client**. Calling it without client credentials throws `MissingClientAuthError`.

> [!NOTE]
> **DPoP:** `getTokenOnBehalfOf()` forwards the incoming access token as the
> [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) `subject_token`
> and relies on Auth0 to handle any DPoP-specific behavior for that token.

### `getTokenOnBehalfOf()` Return Value

On success, the method returns an `OnBehalfOfTokenResult` object containing:

- `accessToken`: The exchanged access token issued for the downstream API.
- `expiresAt`: The access token expiration time, represented in seconds since the Unix epoch.
- `scope`: The scope granted for the exchanged token, if returned.
- `tokenType`: The returned token type, if returned.
- `issuedTokenType`: The returned RFC 8693 issued token type, if returned.

### Error Handling

Two error types cover the failure scenarios you will encounter:

- `MissingClientAuthError`: Thrown when `clientId` or client credentials (`clientSecret` or `clientAssertionSigningKey`) are not configured on the plugin. This is a configuration error and will not be resolved at request time.
- `TokenExchangeError`: Thrown when Auth0 rejects the exchange. The error preserves the OAuth error code and description from Auth0 (for example, `invalid_target` when the client is not authorized to access the downstream API).

Both are exported from `@auth0/auth0-fastify-api`:

```ts
import fastifyAuth0Api, { MissingClientAuthError, TokenExchangeError } from '@auth0/auth0-fastify-api';

try {
  const obo = await fastify.auth0Client!.getTokenOnBehalfOf(incomingAccessToken, {
    audience: 'https://calendar-api.example.com',
  });
} catch (err) {
  if (err instanceof MissingClientAuthError) {
    // Plugin is not configured with client credentials — fix the registration options.
    throw err;
  }
  if (err instanceof TokenExchangeError) {
    // Auth0 rejected the exchange. err.message contains the error_description from Auth0.
    reply.code(502).send({ error: 'upstream_exchange_failed', detail: err.message });
    return;
  }
  throw err;
}
```

### Verifying an Exchanged Token on the Downstream API

When the downstream API (for example, the Calendar API in the examples above) receives the exchanged token, it should verify the token, confirm that the current actor is an expected caller, and optionally record the delegation chain for audit logging.

The exchanged token contains an `act` claim that identifies the actor that performed the exchange:

```json
{
  "sub": "auth0|user123",
  "aud": "https://calendar-api.example.com",
  "azp": "<AUTH0_CLIENT_ID>",
  "act": {
    "sub": "<AUTH0_CLIENT_ID>"
  }
}
```

On the Calendar API (also a Fastify app using this plugin):

```ts
import fastifyAuth0Api, { getCurrentActor, getDelegationChain } from '@auth0/auth0-fastify-api';

const calendarApi = Fastify({ logger: true });

calendarApi.register(fastifyAuth0Api, {
  domain: '<AUTH0_DOMAIN>',
  audience: 'https://calendar-api.example.com',
});

const ALLOWED_ACTORS = ['<MCP_SERVER_CLIENT_ID>'];

calendarApi.register(() => {
  calendarApi.get(
    '/meetings',
    {
      preHandler: calendarApi.requireAuth(),
    },
    async (request: FastifyRequest) => {
      // Use only the top-level act.sub for authorization decisions (RFC 8693 §4.1).
      const currentActor = getCurrentActor(request.user);
      if (!currentActor || !ALLOWED_ACTORS.includes(currentActor)) {
        throw { statusCode: 403, message: 'Actor not authorized' };
      }

      // Use the full delegation chain for logging or audit only — never for authorization.
      const delegationChain = getDelegationChain(request.user);
      request.log.info({ user: request.user.sub, currentActor, delegationChain }, 'delegated_request');

      return { meetings: [] };
    }
  );
});
```

> [!IMPORTANT]
> Only the outermost `act.sub`, returned by `getCurrentActor()`, should be used for authorization
> decisions. Nested `act` values represent prior actors in the delegation chain and are informational
> only, per [RFC 8693 §4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1).

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
