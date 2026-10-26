# Examples

- [Configuration](#configuration)
  - [Basic configuration](#basic-configuration)
  - [Discovery Cache](#discovery-cache)
  - [Configuring the mounted routes](#configuring-the-mounted-routes)
- [The `ServerClient` instance](#the-serverclient-instance)
- [Protecting Routes](#protecting-routes)
- [Requesting an Access Token to call an API](#requesting-an-access-token-to-call-an-api)
- [Login and Signup using Passkeys](#login-and-signup-using-passkeys)
  - [How it works](#how-it-works)
  - [The routes](#the-routes)
  - [Handling errors and retries](#handling-errors-and-retries)
  - [Verifying the email address or phone number at signup](#verifying-the-email-address-or-phone-number-at-signup)
  - [The browser side](#the-browser-side)
  - [Securing the routes](#securing-the-routes)
- [Login using Custom Token Exchange](#login-using-custom-token-exchange)
  - [Performing a delegation exchange without a session](#performing-a-delegation-exchange-without-a-session)
  - [Using actor tokens for delegation](#using-actor-tokens-for-delegation)
  - [Authenticating within an organization](#authenticating-within-an-organization)
- [Impersonation via Session Transfer](#impersonation-via-session-transfer)
  - [Initiator: requesting a Session Transfer Token and redirecting](#initiator-requesting-a-session-transfer-token-and-redirecting)
  - [Target: redeeming the Session Transfer Token](#target-redeeming-the-session-transfer-token)
  - [Reading the `act` claim on the impersonation session](#reading-the-act-claim-on-the-impersonation-session)
  - [Handling errors](#handling-errors)
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

## Login and Signup using Passkeys

Passkeys let users sign up and log in with a device credential (a fingerprint, a face scan or a security key) instead of a password. A signup can also verify the user's email address and phone number with one-time codes before the account is created.

The plugin does not mount routes for this flow. You add three routes that call `fastify.auth0Client.passkey`, so your own validation, rate limits and bot checks sit in front of them. After a successful flow the session is the same as after an OIDC login, so `getUser()`, `getSession()` and `getAccessToken()` work as usual. The [passkeys example app](https://github.com/auth0/auth0-fastify/tree/main/examples/example-fastify-web-passkeys) has these routes and a complete page for them.

> [!IMPORTANT]
> Check these in your [Auth0 Dashboard](https://manage.auth0.com) first:
>
> 1. **Enable the passkey authentication method**: go to **Authentication** > **Database** > your connection > **Authentication Methods** > **Passkey**. The connection's name is the `realm` in the routes below. Without a `realm`, Auth0 uses the tenant's Default Directory.
> 2. **Enable the passkey grant**: go to your application > **Advanced Settings** > **Grant Types** and enable **Passkey**. `passkey.complete()` fails without it.
> 3. **Set up a [custom domain](https://auth0.com/docs/customize/custom-domains)** and use it as the plugin's `domain`. Passkeys are bound to it, so they do not work on the default `*.auth0.com` domain. The page that asks for the passkey must be served over HTTPS from your custom domain or one of its subdomains (usually a subdomain, because Auth0 serves the custom domain itself). `http://localhost` does not work: the browser refuses the passkey with a `SecurityError`. The example app's README shows [how to run it on your machine](https://github.com/auth0/auth0-fastify/blob/main/examples/example-fastify-web-passkeys/README.md#where-to-run-it).
> 4. **Use a client secret**: `startSignup()` and `startLogin()` accept only a `clientSecret` as their client credential, not a private key JWT or mTLS. Set the application's authentication method to **Client Secret**. `complete()` works with any method.
>
> Read [the Auth0 docs](https://auth0.com/docs/authenticate/database-connections/passkeys) to learn more about passkeys.

### How it works

Every passkey flow takes two requests, because the WebAuthn calls (`navigator.credentials.create()` and `navigator.credentials.get()`) only run in the browser:

1. The browser asks your server to start. Your server calls `passkey.startSignup()` or `passkey.startLogin()` and returns `authnParamsPublicKey`, the options for the browser call.
2. The browser runs its call and sends the credential back. Your server calls `passkey.complete()`, which exchanges it for tokens and writes the session.

Between the two requests the SDK keeps the flow, including the Auth0 `authSession`, in the encrypted `HttpOnly` cookie `__a0_passkey_tx`, for as long as Auth0 allows the flow (the `timeout` it returns with the options: currently 60 seconds, or 15 minutes when the signup needs codes). The `authSession` never reaches your code or the browser, and a new start replaces the pending flow in that browser. Serve the page and these routes from the same origin, so that the browser sends the cookies back on its own.

> [!WARNING]
> Pass `{ request, reply }` as the second argument of every passkey call, so the SDK can read and write that cookie. Without it the call throws `MissingStoreOptionsError`, and `startSignup()` has already reached Auth0 by then (as of the `@auth0/auth0-server-js` 1.17.0 that the plugin builds on), so the codes may already be on their way.

### The routes

Register the plugin as in [Basic configuration](#basic-configuration), then add the routes:

```ts
import type { FastifyRequest } from 'fastify';
import {
  isMfaRequiredError,
  MissingRequiredArgumentError,
  MissingTransactionError,
  PasskeyGetTokenError,
  SessionExpiredError,
} from '@auth0/auth0-fastify';
import type {
  PasskeyCredentialResponse,
  PasskeyRegisterOptions,
  PasskeyVerificationCodes,
} from '@auth0/auth0-fastify';

// The database connection that has the Passkey authentication method turned on.
const realm = '<AUTH0_CONNECTION>';

// Auth0 sees your server's address. This header tells it the user's address (see "Securing the routes" below).
const forwardIp = (request: FastifyRequest) =>
  request.ip ? { headers: { 'auth0-forwarded-for': request.ip } } : undefined;

// 1a. Start a signup. When the connection verifies the email address or phone number, Auth0 sends the codes now.
fastify.post<{ Body: PasskeyRegisterOptions }>('/api/passkey/signup/start', async (request, reply) => {
  // `request.body` is the browser's choice: validate it first (see "Securing the routes"), or it can set options such
  // as `organization` and `userMetadata`. The connection (`realm`) comes from the server.
  const { authnParamsPublicKey, verificationRequired } = await fastify.auth0Client!.passkey.startSignup(
    { ...request.body, realm },
    { request, reply },
    forwardIp(request)
  );

  return { authnParamsPublicKey, verificationRequired: verificationRequired ?? [] };
});

// 1b. Start a login.
fastify.post('/api/passkey/login/start', async (request, reply) => {
  const { authnParamsPublicKey } = await fastify.auth0Client!.passkey.startLogin(
    { realm },
    { request, reply },
    forwardIp(request)
  );

  return { authnParamsPublicKey };
});

// 2. Complete a signup or a login. The SDK reads the flow from its cookie, exchanges the passkey for tokens and
//    writes the session.
fastify.post<{ Body: { credential: PasskeyCredentialResponse; verification?: PasskeyVerificationCodes } }>(
  '/api/passkey/complete',
  async (request, reply) => {
    const { credential, verification } = request.body;

    try {
      await fastify.auth0Client!.passkey.complete(
        { credential, verification },
        { request, reply },
        forwardIp(request)
      );

      return { status: 'complete' };
    } catch (error) {
      if (error instanceof PasskeyGetTokenError && error.isRetryable) {
        // A wrong code: ask again for the identifiers still listed, and send the same passkey.
        return reply.code(400).send({ status: 'retry', verificationRequired: error.verificationRequired ?? [] });
      }
      if (error instanceof PasskeyGetTokenError && error.statusCode === 429) {
        // Send the same request again later. Auth0 can say in `retry-after` how many seconds to wait.
        const retryAfter = Number(error.headers?.get('retry-after'));
        return reply.code(429).send({ status: 'wait', ...(retryAfter > 0 && { retryAfterSeconds: retryAfter }) });
      }
      if (isMfaRequiredError(error)) {
        // The passkey was accepted, but the user must also complete MFA. This route stops here and keeps no token: to
        // continue, keep `error.cause.mfa_token` on the server and use `fastify.auth0Client!.mfa`.
        return { status: 'mfa_required' };
      }
      if (error instanceof SessionExpiredError) {
        // The passkey was accepted, but the ID token says the session has already expired: no session, and the flow
        // is gone. Ask the user to sign in again.
        return reply.code(400).send({ status: 'session_expired' });
      }
      if (error instanceof MissingTransactionError) {
        return reply.code(400).send({ status: 'restart' }); // no flow, or it expired: start again
      }
      if (
        error instanceof MissingRequiredArgumentError ||
        (error instanceof PasskeyGetTokenError && error.cause?.error === 'invalid_request')
      ) {
        return reply.code(400).send({ status: 'invalid' }); // for example a missing code: fix the input, send again
      }

      // Log a summary, never the whole error: the `cause` of an Auth0 error can hold an `mfa_token`, and the error of
      // a session store can hold the session. A server or network failure has no `cause.error`, only `cause.message`.
      request.log.warn(
        error instanceof PasskeyGetTokenError
          ? { errorCode: error.cause?.error || error.cause?.message }
          : { errorMessage: error instanceof Error ? error.message : String(error) },
        'passkey.complete() failed'
      );
      return reply.code(400).send({ status: 'failed' });
    }
  }
);
```

The `status` values (`complete`, `retry`, `wait` and so on) are only a convention between these routes and the browser code below. Use whatever fits your frontend. The routes skip body validation to stay short: add the schemas from [Securing the routes](#securing-the-routes) before you go live.

`startSignup()` and `startLogin()` throw a `PasskeyRegisterError` or a `PasskeyChallengeError` when Auth0 refuses the request, for example because the user already exists, a code could not be sent, or Auth0 rate limits the call. Nothing is stored then. Fastify's default error handler answers with `error.statusCode` (for example 400 or 429) and Auth0's description in `message`. In a real app, catch these errors, for example with `fastify.setErrorHandler()` as the example app does, and show your own message.

### Handling errors and retries

`passkey.complete()` deletes the stored flow once Auth0 has used the auth session: on success, on `mfa_required`, when Auth0 reports the auth session as used, expired or invalid, and when the ID token organization does not match. It also deletes the flow before it creates the session, so the flow is gone when that step fails: with a `SessionExpiredError`, or when your session store throws. After any other failure the flow is kept, and you can call `complete()` again with the same credential.

| `complete()` throws | Meaning | The route answers | What the browser does |
|---|---|---|---|
| `PasskeyGetTokenError` with `isRetryable` | A one-time code was wrong. `error.verificationRequired` lists the identifiers that still need a code (if it is missing, ask for the same ones again). | `retry` | Ask for those codes only, then send the same credential again. |
| `PasskeyGetTokenError` with `statusCode` 429 | Rate limited. Auth0 checks this before it uses the attempt. | `wait`, with `retryAfterSeconds` when Auth0 sent a `retry-after` header | Wait that long, then send the same request again. |
| `isMfaRequiredError(error)` | The passkey and any codes were accepted, but the user must complete MFA. No session yet. | `mfa_required` | The routes above stop here and keep no token. To continue, keep `error.cause.mfa_token` on the server (never send it to the browser) and use `fastify.auth0Client.mfa`, see [Handling an `mfa_required` response](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-server-js/EXAMPLES.md#handling-an-mfa_required-response). The example app shows a message and points the user to OIDC Login. |
| `SessionExpiredError` | The passkey was accepted, but the `session_expiry` claim of the ID token has already passed, so no session was created. The flow is gone. | `session_expired` | Tell the user, and send them to sign in again, for example with OIDC Login. |
| `MissingTransactionError` | No flow to complete: none was started, it expired, a newer start replaced it (for example in another tab), or the cookie cannot be read (for example after the session secret changed). Auth0 was not called. | `restart` | Start a new flow. |
| `MissingRequiredArgumentError`, or `PasskeyGetTokenError` with `cause.error` set to `invalid_request` | The request was incomplete or invalid: the credential cannot be read, or a code is missing or blank. The SDK checks the credential and the codes before it calls Auth0, and the flow is kept. | `invalid` | Fix the input, then send again. |
| Anything else | Auth0 refused the exchange for another reason (see `error.cause?.error`, for example `invalid_grant` when the attempt expired or was already used), could not be reached (the error has no `statusCode`), or your session store threw while it saved the session. | `failed` | Send the same request once more, and start a new flow if that fails too. A flow that is over answers `restart` the second time. |

Use `isRetryable` to tell a wrong code from a failure that ends the attempt, and never the HTTP status or the error description: they are the same for both, because both are an `invalid_grant`. The errors never carry the `authSession`, but their `cause` can hold an `mfa_token`, so do not log or return a whole error.

### Verifying the email address or phone number at signup

When the connection verifies identifiers at signup, `startSignup()` returns `verificationRequired` (for example `['email', 'phone']`) and Auth0 has sent a one-time code to each listed identifier. Ask the user for the codes **before** you call `navigator.credentials.create()`, so nobody is left with a passkey for an account that was never created. Then send the codes with the credential. The profile field is `phoneNumber`, but its identifier and its code are `phone`:

```json
{ "credential": { "id": "...", "rawId": "...", "type": "public-key", "response": {} }, "verification": { "email": "123456", "phone": "654321" } }
```

- Send a code for every identifier in the list (a missing or blank one is answered with `invalid`).
- After a wrong code, ask again only for the identifiers in `error.verificationRequired`, and send the **same** credential, kept in page memory: the user sees no second passkey prompt. The SDK keeps the shorter list too.
- To send new codes, call the signup start route again before the passkey exists. That starts a new flow and sends new codes: the user enters the newest ones, and the passkey is created with the options from the latest response.
- The user has 15 minutes to enter the codes, retries included (Auth0's current `timeout` for a signup with codes). Any other passkey flow started in that browser, in any tab, replaces the pending signup, which can then no longer be completed.
- To choose how the phone code is delivered, pass `deliveryMethod` (`'text'` or `'voice'`) with the `phoneNumber`. Leave it out to let Auth0 use the channel the connection supports (SMS when it supports both or none). A channel that the connection does not support makes the start call fail.

Only the identifiers you pass are verified, using the connection's signup verification settings: an email address must be set up for verification with a one-time code (a verification link does not use this flow), and so must a phone number. See the [server SDK documentation](https://github.com/auth0/auth0-auth-js/blob/main/packages/auth0-server-js/EXAMPLES.md#verifying-the-email-or-phone-number-at-signup) for the details.

### The browser side

The WebAuthn calls are the same in every framework:

1. `POST` to the start route and read `authnParamsPublicKey`. For a signup with `verificationRequired`, ask the user for the codes now.
2. Turn the base64url fields of `authnParamsPublicKey` (`challenge`, `user.id` and the credential ids) into `ArrayBuffer`s, then call `navigator.credentials.create({ publicKey })` (signup) or `navigator.credentials.get({ publicKey })` (login). Where the browser has them, `PublicKeyCredential.parseCreationOptionsFromJSON()` and `parseRequestOptionsFromJSON()` do the conversion.
3. Turn the credential into base64url strings, and `POST` it, with the codes, to the complete route. On `retry`, ask for the listed codes and `POST` again with the same credential. On `restart`, start again.

```js
async function post(path, body = {}) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  return { httpStatus: response.status, ...(await response.json()) };
}

async function loginWithPasskey() {
  const start = await post('/api/passkey/login/start');
  if (!start.authnParamsPublicKey) return start; // Auth0 refused the start: show start.message

  const publicKey = requestOptions(start.authnParamsPublicKey);
  const credential = await navigator.credentials.get({ publicKey });

  return post('/api/passkey/complete', { credential: serialize(credential) });
}

// `askForCodes(identifiers)` is your own UI. It resolves with one code for each identifier, for example
// { email: '123456', phone: '654321' }.
async function signUpWithPasskey(profile) {
  const start = await post('/api/passkey/signup/start', profile);
  if (!start.authnParamsPublicKey) return start; // for example the user already exists: show start.message

  // Ask for the codes first: the passkey is only created once the user has them.
  let identifiers = start.verificationRequired;
  let verification = identifiers.length > 0 ? await askForCodes(identifiers) : undefined;
  const publicKey = creationOptions(start.authnParamsPublicKey);
  const credential = serialize(await navigator.credentials.create({ publicKey }));

  let result = await post('/api/passkey/complete', { credential, verification });
  while (result.status === 'retry') {
    // A wrong code: ask again for the identifiers that are still listed, and send the same credential.
    if (result.verificationRequired.length > 0) identifiers = result.verificationRequired;
    verification = await askForCodes(identifiers);
    result = await post('/api/passkey/complete', { credential, verification });
  }

  return result; // result.status is 'complete', or one of the other statuses in the table above
}
```

This is the short version. The example app also handles a cancelled prompt, a network error, `wait`, `restart` and `failed`.

<details>
<summary>The helpers: <code>creationOptions</code>, <code>requestOptions</code> and <code>serialize</code></summary>

```js
// Auth0 sends binary values as base64url strings. The WebAuthn API wants ArrayBuffers.
function fromBase64url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer;
}

function toBase64url(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const decodeIds = (descriptors) =>
  descriptors.map((descriptor) => ({ ...descriptor, id: fromBase64url(descriptor.id) }));

// `authnParamsPublicKey` from the signup start route, ready for `navigator.credentials.create({ publicKey })`.
function creationOptions(options) {
  return {
    ...options,
    challenge: fromBase64url(options.challenge),
    user: { ...options.user, id: fromBase64url(options.user.id) },
    ...(options.excludeCredentials && { excludeCredentials: decodeIds(options.excludeCredentials) }),
  };
}

// `authnParamsPublicKey` from the login start route, ready for `navigator.credentials.get({ publicKey })`.
function requestOptions(options) {
  return {
    ...options,
    challenge: fromBase64url(options.challenge),
    ...(options.allowCredentials && { allowCredentials: decodeIds(options.allowCredentials) }),
  };
}

// The credential the browser made, as the JSON the complete route takes. Send only these fields:
// do not send `credential.toJSON()`, because Auth0 rejects its extra fields.
function serialize(credential) {
  const raw = credential.response;
  const response = { clientDataJSON: toBase64url(raw.clientDataJSON) };
  if (raw.attestationObject) response.attestationObject = toBase64url(raw.attestationObject);
  if (raw.authenticatorData) response.authenticatorData = toBase64url(raw.authenticatorData);
  if (raw.signature) response.signature = toBase64url(raw.signature);
  if (raw.userHandle) response.userHandle = toBase64url(raw.userHandle);
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    ...(credential.authenticatorAttachment && { authenticatorAttachment: credential.authenticatorAttachment }),
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}
```

</details>

If `complete()` throws `MissingTransactionError` on every attempt, check that the browser decodes the base64url `challenge` to bytes, instead of using the characters of the string. Send only the fields that `serialize()` returns: Auth0 rejects the extra fields of `credential.toJSON()` with an `invalid_request` error.

### Securing the routes

These routes are open to anyone who can reach them, and the signup start route can make Auth0 send an email, an SMS or a voice call to any address or number. Add these before you go live:

- **Validate the body, and drop what you did not ask for.** With Fastify's default settings, a schema with `additionalProperties: false` removes every property it does not list, so the browser cannot choose the `organization`, `userMetadata` or any other option of `startSignup()`, and Auth0 never gets a credential field it rejects. Add `{ schema: { body: signupBody }, bodyLimit: 32 * 1024 }` to the signup start route and `{ schema: { body: completeBody }, bodyLimit: 32 * 1024 }` to the complete route. A credential is a few KB, and the default `bodyLimit` is 1 MiB. `startSignup()` also accepts a `username`: if your connection signs users up by username, add it to `SignupBody`, to the `properties` of `signupBody` and to its `anyOf`, or Fastify drops it and a signup with only a `username` is refused.

  <details>
  <summary>The schemas</summary>

  ```ts
  import type {
    PasskeyCredentialResponse,
    PasskeyDeliveryMethod,
    PasskeyVerificationCodes,
  } from '@auth0/auth0-fastify';

  type SignupBody = {
    name?: string;
    deliveryMethod?: PasskeyDeliveryMethod;
  } & ({ email: string; phoneNumber?: string } | { phoneNumber: string; email?: string });

  const signupBody = {
    type: 'object',
    additionalProperties: false,
    properties: {
      email: { type: 'string', format: 'email', maxLength: 254 },
      phoneNumber: { type: 'string', pattern: '^\\+[1-9]\\d{6,14}$' }, // E.164
      name: { type: 'string', minLength: 1, maxLength: 100 },
      deliveryMethod: { type: 'string', enum: ['text', 'voice'] },
    },
    anyOf: [{ required: ['email'] }, { required: ['phoneNumber'] }],
  } as const;

  interface CompleteBody {
    credential: PasskeyCredentialResponse;
    verification?: PasskeyVerificationCodes;
  }

  const completeBody = {
    type: 'object',
    required: ['credential'],
    additionalProperties: false,
    properties: {
      credential: {
        type: 'object',
        required: ['id', 'rawId', 'type', 'response'],
        additionalProperties: false,
        properties: {
          id: { type: 'string' },
          rawId: { type: 'string' },
          type: { type: 'string' },
          authenticatorAttachment: { type: 'string' },
          clientExtensionResults: { type: 'object' },
          response: {
            type: 'object',
            required: ['clientDataJSON'],
            additionalProperties: false,
            properties: {
              clientDataJSON: { type: 'string' },
              attestationObject: { type: 'string' },
              authenticatorData: { type: 'string' },
              signature: { type: 'string' },
              userHandle: { type: 'string' },
            },
          },
        },
      },
      // One code per identifier, at most 10 characters (Auth0 rejects longer ones).
      verification: {
        type: 'object',
        additionalProperties: false,
        properties: {
          email: { type: 'string', minLength: 1, maxLength: 10 },
          phone: { type: 'string', minLength: 1, maxLength: 10 },
        },
      },
    },
  } as const;
  ```

  </details>

- **Rate limit the routes** with [`@fastify/rate-limit`](https://github.com/fastify/fastify-rate-limit), the signup start route the strictest. Every call sends new codes, so a route that anyone can call can be used to send messages to any address or number. Do not rely only on Auth0's limits: also limit per email address or phone number, add a bot check (for example a CAPTCHA), and accept only the phone country codes you serve. The other two routes call Auth0 too, so give them a higher limit. A start call can also fail because the address already has an account (as a `PasskeyRegisterError`), so the signup route can be used to find out whether an address is registered: this is another reason to limit it. The default store is in memory, per process: use a shared store when you run several instances.

  ```ts
  import rateLimit from '@fastify/rate-limit';

  // Await it, and register it before the routes: a route defined before the plugin has loaded is silently not limited.
  await fastify.register(rateLimit, { global: false });

  fastify.post<{ Body: PasskeyRegisterOptions }>(
    '/api/passkey/signup/start',
    { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } },
    async (request, reply) => {
      // ...
    }
  );
  ```

- **Set `trustProxy`** to the IP addresses or CIDR ranges of the proxies in front of your app (for example `'10.0.0.0/8'`), so that `request.ip` is the user's address. Do not set it to `true`: that trusts every `X-Forwarded-For` entry, so a client can choose its own address and get around the rate limit. Do not set it to a number of proxies either: that cannot tell a proxy from a client that connects directly, and Fastify 5.12.1 and later trust nothing for it. Auth0 uses the `auth0-forwarded-for` header only for applications with **Trust Token Endpoint IP Header** turned on (**Advanced Settings** > **OAuth**), and `startSignup()` rejects a value that is not a valid IP address.
- **Accept only requests from your own page.** The routes write cookies, so refuse a `POST` that comes from another site. `fetch()` always sends `Origin` with a `POST`, and a page on another site cannot fake it. For example, for the routes under `/api/`:

  ```ts
  const appOrigin = new URL('<APP_BASE_URL>').origin;

  fastify.addHook('onRequest', async (request, reply) => {
    // Look at the route that matched, not at `request.url`: the router also matches a path such as /%61pi/...
    const route = request.routeOptions.url ?? '';
    if (request.method === 'POST' && route.startsWith('/api/') && request.headers.origin !== appOrigin) {
      return reply.code(403).send({ status: 'forbidden' });
    }
  });
  ```

- **Send one complete request at a time**, for example by disabling the submit button while a request is pending, and cap the wrong-code retries in the browser (the example stops after 5). Parallel requests can use up the attempts Auth0 allows.
- **Never log the credential, the codes or a whole error.** Log `error.cause?.error`, or `error.cause?.message` for a server or network failure, instead.

## Login using Custom Token Exchange

Custom Token Exchange lets you create an Auth0 session from a token you already hold (for example a Google ID token or a token from a legacy system), without sending the user through a browser login. This needs a [Token Exchange Profile](https://auth0.com/docs/authenticate/custom-token-exchange) set up in your Auth0 tenant.

The plugin does not mount a route for this flow. You call it yourself from your own route using `fastify.auth0Client`, in the same way you would use `loginBackchannel()`.

Use `loginWithCustomTokenExchange()` when you want to exchange the token and store the result as a user session:

```ts
fastify.post('/custom-token-exchange', async (request, reply) => {
  await fastify.auth0Client!.loginWithCustomTokenExchange(
    {
      subjectToken: '<EXTERNAL_TOKEN>',
      subjectTokenType: 'urn:acme:legacy-token',
      audience: '<AUTH0_AUDIENCE>',
      scope: 'openid profile email',
    },
    { request, reply }
  );

  return reply.send({ ok: true });
});
```

After the exchange, the tokens are written to the session cookie, so the user is logged in. You can then use `getUser()`, `getSession()`, and `getAccessToken()` the same way as after any other login.

Because `loginWithCustomTokenExchange()` writes the session cookie, pass the store options (`{ request, reply }`) so the SDK can read and write it, just like the other session methods in this plugin.

> [!NOTE]
> The `openid` scope is needed for `loginWithCustomTokenExchange()` to receive an ID token and fill in the session user. If you leave `openid` out, the SDK adds it for you. If you pass no `scope` at all, the SDK uses `openid profile email offline_access`.

### Performing a delegation exchange without a session

Use `customTokenExchange()` when you need a token to call another API but you do not want to create or change the user session. This fits delegation and impersonation flows:

```ts
fastify.post('/delegate', async (request, reply) => {
  const tokenResponse = await fastify.auth0Client!.customTokenExchange({
    subjectToken: '<INCOMING_ACCESS_TOKEN>',
    subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    audience: '<DOWNSTREAM_API_AUDIENCE>',
  });

  // Use tokenResponse.accessToken to call the downstream API.
  return reply.send({ accessToken: tokenResponse.accessToken });
});
```

No session is read or written. You can omit the store options (`{ request, reply }`) unless you run the plugin in [MCD resolver mode](#resolver-mode), where they are used only to resolve the domain.

### Using actor tokens for delegation

When an intermediate service acts on behalf of a user, pass `actorToken` and `actorTokenType` together. Both are needed when you use actor tokens:

```ts
const tokenResponse = await fastify.auth0Client!.customTokenExchange({
  subjectToken: '<USER_TOKEN>',
  subjectTokenType: 'urn:acme:user-token',
  actorToken: '<SERVICE_TOKEN>',
  actorTokenType: 'urn:acme:service-token',
  audience: '<AUTH0_AUDIENCE>',
});

// tokenResponse.act holds the actor claim from the issued token, e.g. { sub: 'service-account-id' }.
console.log(tokenResponse.act?.sub);
```

> [!IMPORTANT]
> When an actor token is sent, Auth0 does not return a refresh token, even if `offline_access` is in the scope. This is true for both methods. For `loginWithCustomTokenExchange()`, it means `getAccessToken()` will throw once the access token expires, because it cannot refresh on its own. Run the exchange again to get a new token.

### Authenticating within an organization

To exchange a token within an [organization](https://auth0.com/docs/manage-users/organizations) context, pass the `organization` option with the organization ID or name. The user is authenticated within that organization, and the organization ID is included in the access token. This works with both methods:

```ts
fastify.post('/custom-token-exchange', async (request, reply) => {
  await fastify.auth0Client!.loginWithCustomTokenExchange(
    {
      subjectToken: '<EXTERNAL_TOKEN>',
      subjectTokenType: 'urn:acme:legacy-token',
      organization: '<ORGANIZATION_ID_OR_NAME>',
    },
    { request, reply }
  );

  return reply.send({ ok: true });
});
```

## Impersonation via Session Transfer

Impersonation via Session Transfer builds on Custom Token Exchange and lets a support or admin application log an agent **into a target web application as a customer**. A support engineer can reproduce a customer's exact experience without ever knowing their password, and the agent is recorded in the `act` claim so every impersonation is auditable.

There are two roles, usually two separate applications:

- **Initiator** — your support/admin app. It requests a short-lived, single-use **Session Transfer Token (STT)** and redirects the agent's browser to the target app's login URL carrying the STT.
- **Target** — the customer's own web app. Its login route forwards the STT to `/authorize`, where Auth0 redeems it and establishes an ephemeral, device-bound session **as the customer**.

The STT is **opaque, single-use, and short-lived (~60s)**. The SDK requests it, hands it back, and helps you build the redirect. It never decodes, validates, caches, or persists it.

> [!IMPORTANT]
> This is a two-client, two-role flow. Both clients must live on the **same Auth0 tenant**, and the tenant settings below are configured out of band through the Management API or the Dashboard. They are not SDK code.
>
> - The tenant needs the `cte_session_transfer_token` feature flag enabled. Contact Auth0 support to turn it on.
> - The **initiator client** needs `token_exchange.allow_any_profile_of_type: ["custom_authentication"]` and `session_transfer.can_create_session_transfer_token: true`.
> - The **target client** needs `session_transfer.delegation.allow_delegated_access: true`, `session_transfer.allowed_authentication_methods` including `"query"`, and a device-binding mode via `session_transfer.delegation.enforce_device_binding` (`"ip"` by default).
> - A **Custom Token Exchange Action** must validate your `subject_token`, call `setUserById()` for the customer, and call `setActor()` for the agent. An STT is only issued when an actor is set.
> - The target app needs a **non-localhost callback URL** registered. STT redemption rejects `localhost` redirect URIs, so use a real domain or a tunnel during development. This is about the app's registered OAuth callback URL, which is a tenant setting. It is not about `targetLoginUrl`, where the SDK does allow `http://localhost` so you can point at a local target app.
>
> See the [Custom Token Exchange documentation](https://auth0.com/docs/authenticate/custom-token-exchange) for the full setup.

### Initiator: requesting a Session Transfer Token and redirecting

The plugin does not mount a route for this flow, in the same way it does not mount one for Custom Token Exchange. You call it from your own route using `fastify.auth0Client`.

The agent must be **logged in** to the initiator app, because the SDK sources the actor from the agent's current session ID token by default. Run your own authorization check first (_is this agent allowed to impersonate this customer, right now?_), then call `requestSessionTransferToken()`:

```ts
fastify.post('/impersonate', { preHandler: hasSessionPreHandler }, async (request, reply) => {
  const result = await fastify.auth0Client!.requestSessionTransferToken(
    {
      // Your own proof of which customer to impersonate, validated by your Action.
      // The SDK never produces this. You supply it in whatever form your Action expects.
      subjectToken: '<CUSTOMER_PROOF_TOKEN>',
      subjectTokenType: 'urn:acme:customer-subject',
      // Optional: forward custom context to your Action via `event.request.body`.
      extra: { reason: 'Investigating TCK-4821' },
    },
    { request, reply }
  );

  // Build the redirect to the TARGET app's login URL, a trusted app-controlled value.
  const url = fastify.auth0Client!.buildSessionTransferRedirect('https://app.example.com/auth/login', result);

  return reply.redirect(url.href);
});
```

Pass the store options (`{ request, reply }`) so the SDK can read the agent's session to source the actor.

By default the actor is the agent session's ID token. To supply the acting party yourself, pass `actor`. This is the way to run the flow from a route with no agent session, for example a machine-to-machine job:

```ts
const result = await fastify.auth0Client!.requestSessionTransferToken(
  {
    subjectToken: '<CUSTOMER_PROOF_TOKEN>',
    subjectTokenType: 'urn:acme:customer-subject',
    actor: { token: '<AGENT_ID_TOKEN>' }, // `type` defaults to the ID token URN
  },
  { request, reply }
);
```

If the customer belongs to an [organization](https://auth0.com/docs/manage-users/organizations), there is an `organization` on both calls. They do different things, so pick based on what you need:

```ts
const result = await fastify.auth0Client!.requestSessionTransferToken(
  {
    subjectToken: '<CUSTOMER_PROOF_TOKEN>',
    subjectTokenType: 'urn:acme:customer-subject',
    organization: '<ORGANIZATION_ID_OR_NAME>',
  },
  { request, reply }
);

const url = fastify.auth0Client!.buildSessionTransferRedirect('https://app.example.com/auth/login', result, {
  organization: '<ORGANIZATION_ID_OR_NAME>',
});
```

These are two separate parameters on two separate requests, and one does not imply the other:

- On the mint, the tenant validates the organization against the client's organization settings while issuing the STT. An organization the client is not allowed to use fails at that call, instead of the STT being issued without it.
- On the redirect, it is forwarded to the target's `/authorize` as part of a normal interactive login, the same as any other org-scoped login.

The redirect one is what scopes the session the target ends up with. Passing `organization` only on the mint gets you the validation, but it does not org-scope the target's session, so pass it on the redirect as well when you need that.

An `organization` the tenant rejects surfaces as a `TokenExchangeError`. A blank one throws `OrganizationValidationError` before the session is read or any network call is made.

Branch on `result.issuedTokenType`, never on `result.tokenType`. For an STT the server returns `token_type: "N_A"`, which is informational only. A successful STT exchange always sets `issuedTokenType` to `urn:auth0:params:oauth:token-type:session_transfer_token`. The SDK surfaces exactly what the server returned rather than assuming the URN, so check it yourself before treating the result as an STT:

```ts
const STT_TOKEN_TYPE = 'urn:auth0:params:oauth:token-type:session_transfer_token';

if (result.issuedTokenType !== STT_TOKEN_TYPE) {
  // Not a session transfer token. Do not treat it as one.
  throw new Error(`Unexpected issued token type: ${result.issuedTokenType}`);
}
```

> [!IMPORTANT]
> An **actor is mandatory** for an STT. That is what makes this auditable impersonation ("X acting as Y") rather than a silent account takeover. If you pass no explicit `actor` and no usable session ID token can be resolved (no logged-in agent, or an expired ID token with no refresh token), the SDK throws a `TokenExchangeError` with code `actor_unavailable` **before any network call**. When the agent's session ID token has expired and a refresh token is available, the SDK refreshes it automatically and persists the refreshed session.

> [!WARNING]
> `buildSessionTransferRedirect()` attaches a single-use credential to the URL, so `targetLoginUrl` **must be a trusted, app-controlled value**. Never derive it from untrusted input such as a `returnTo` query parameter, or the token could leak to an attacker-controlled host. The SDK enforces `https` (plain `http` is allowed only for the loopback hosts `localhost`, `127.0.0.1`, and `[::1]`, to support local development) and throws `InvalidConfigurationError` otherwise.

The STT itself is **never persisted**. It is not written to the session or the transaction cookie. Do not cache or persist it either: hand it straight to the redirect and discard it. The only write this flow can make is to the agent's own session, and only when an expired ID token had to be refreshed to serve as the actor.

### Target: redeeming the Session Transfer Token

On the target app, the STT is redeemed as part of a **standard authorization code login**. The mounted `/auth/login` route does this for you: when a request arrives carrying `session_transfer_token`, the plugin forwards it to `/authorize`, together with `organization` when that parameter came along with the STT.

So for the common case the target app needs **no extra code at all**. Register the plugin as usual and point the initiator at the target's login route:

```ts
fastify.register(fastifyAuth0, {
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  appBaseUrl: 'https://app.example.com',
  sessionSecret: '<SESSION_SECRET>',
});

// The initiator redirects the agent to:
//   https://app.example.com/auth/login?session_transfer_token=<STT>
// The plugin forwards the STT to /authorize, and /auth/callback completes the login.
```

`returnTo` keeps working alongside an STT, so you can land the impersonated session on a specific page:

```text
https://app.example.com/auth/login?session_transfer_token=<STT>&returnTo=/orders/4821
```

If you run with `mountRoutes: false` and own your login route, forward the parameter yourself through `authorizationParams`. Mirror what the mounted route does: take the first value when a key is repeated, treat a blank value as absent, and only honour `organization` when an STT is present:

```ts
// Fastify parses a repeated query key into an array, so narrow to a single usable value.
const getQueryValue = (value: string | string[] | undefined): string | undefined => {
  const first = Array.isArray(value) ? value[0] : value;
  const trimmed = first?.trim();
  return trimmed ? trimmed : undefined;
};

fastify.get('/auth/login', async (request, reply) => {
  const query = request.query as {
    session_transfer_token?: string | string[];
    organization?: string | string[];
  };

  const sessionTransferToken = getQueryValue(query.session_transfer_token);
  // Only honour `organization` alongside an STT, which is the pair
  // `buildSessionTransferRedirect` emits. That keeps a plain login unchanged.
  const organization = sessionTransferToken ? getQueryValue(query.organization) : undefined;

  const authorizationUrl = await fastify.auth0Client!.startInteractiveLogin(
    {
      authorizationParams: {
        redirect_uri: 'https://app.example.com/auth/callback',
        ...(sessionTransferToken ? { session_transfer_token: sessionTransferToken } : {}),
      },
      // Prefer the first-class `organization` option over `authorizationParams.organization`.
      // Either form is validated against the returned ID token's claim at the callback, but
      // this one is the documented surface and takes precedence when both are set.
      ...(organization ? { organization } : {}),
    },
    { request, reply }
  );

  return reply.redirect(authorizationUrl.href);
});
```

> [!NOTE]
> The `session_transfer_token` is redeemed as a **query** parameter, so the target client's `session_transfer.allowed_authentication_methods` must include `"query"`. The resulting session is short-lived (hard-capped at 2 hours) and **cannot mint a refresh token**. To continue past that, run the whole flow again.
>
> Because the STT travels as a query parameter, it can land anywhere full URLs are retained: web server access logs, proxy and CDN logs, browser history, and the `Referer` header sent to third-party resources loaded by the redemption page. This is inherent to the redemption mechanism. It is mitigated by the token being **single-use and short-lived (~60s)** and, when configured, **device-bound** through `enforce_device_binding`. A leaked STT is worthless once redeemed or expired. Even so, avoid logging redemption URLs verbatim, and never persist or forward the STT beyond the immediate redirect.

### Reading the `act` claim on the impersonation session

Once the target session is established, the acting agent shows up as the `act` claim on the session user. Read it through the normal session surface to drive UI such as an impersonation banner:

```ts
import type { ActClaim } from '@auth0/auth0-fastify';

fastify.get('/profile', { preHandler: hasSessionPreHandler }, async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });
  const actor = user?.act as ActClaim | undefined;

  return reply.viewAsync('profile.ejs', {
    name: user!.name,
    // When `actor` is set, this session is an impersonation: `actor.sub` is the agent.
    impersonatedBy: actor?.sub,
  });
});
```

The `act` claim is deliberately **not** on the `requestSessionTransferToken()` result. It only appears on the tokens of the session created after the STT is redeemed, which is the target app, not the initiator.

### Handling errors

`requestSessionTransferToken()` throws `TokenExchangeError` when the exchange itself fails. Only `actor_unavailable` is raised by the SDK itself, client-side and before any network call. The server-side conditions are surfaced through `cause`. Argument and configuration problems throw their own error classes instead, listed in the second table below:

```ts
import { TokenExchangeError, TokenExchangeErrorCode } from '@auth0/auth0-fastify';

fastify.post('/impersonate', async (request, reply) => {
  try {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      { subjectToken: '<CUSTOMER_PROOF_TOKEN>', subjectTokenType: 'urn:acme:customer-subject' },
      { request, reply }
    );

    return reply.redirect(
      fastify.auth0Client!.buildSessionTransferRedirect('https://app.example.com/auth/login', result).href
    );
  } catch (error) {
    if (error instanceof TokenExchangeError) {
      // Raised by the SDK: no logged-in agent, or an expired ID token that cannot be refreshed.
      if (error.code === TokenExchangeErrorCode.ACTOR_UNAVAILABLE) {
        return reply.code(401).send({ error: 'Log in again to impersonate.' });
      }

      // Raised by Auth0 and surfaced through `cause`. Read `error_description` too: the
      // server does not yet return a dedicated code for every condition, so some arrive as
      // a generic `invalid_request` with the detail only in the description.
      //   `setactor_required`          — your Action did not call setActor() (planned code)
      //   `session_transfer_disabled`  — the tenant feature flag is off
      const cause = error.cause as { error?: string; error_description?: string } | undefined;
      return reply
        .code(400)
        .send({ error: cause?.error ?? 'Session transfer failed.', detail: cause?.error_description });
    }

    throw error;
  }
});
```

The error codes map cleanly onto the setup steps, which makes them useful for diagnosis.

These are `TokenExchangeError` codes, read from `error.code` or from `error.cause`:

| Code | What it means |
| --- | --- |
| `actor_unavailable` | Raised by the SDK before any network call. No logged-in agent, no explicit `actor`, or an expired ID token with no refresh token. |
| `setactor_required` | Your Custom Token Exchange Action did not call `setActor()`. This is a planned code. Today the tenant returns `invalid_request` and says so in `error_description`, so match on the description as well. |
| `session_transfer_disabled` | The `cte_session_transfer_token` feature flag is off on the tenant. |

The rest are **separate error classes, not `TokenExchangeError`**, so a `catch` that only checks `instanceof TokenExchangeError` will let them through. All of them are raised by the SDK before any network call, so they show up while you are wiring the flow up rather than in production:

| Error class | What it means |
| --- | --- |
| `InvalidConfigurationError` | The `targetLoginUrl` was relative, or used a scheme other than `https` on a non-loopback host. |
| `MissingRequiredArgumentError` | `subjectToken`, `subjectTokenType`, or `targetLoginUrl` was missing or blank. |
| `MissingClientAuthError` | No client credentials configured. An STT requires a confidential client. |
| `OrganizationValidationError` | The `organization` passed to `requestSessionTransferToken()` or `buildSessionTransferRedirect()` was blank. |

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

