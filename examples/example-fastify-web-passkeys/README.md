# Fastify Web App with Passkeys Example

This example shows how to use [`@auth0/auth0-fastify`](../../packages/auth0-fastify) to sign users up and log them in with passkeys, next to the usual OIDC login:

- **Passkey Signup**, with a one-time code for the email address and/or phone number when the connection verifies them.
- **Passkey Login**.
- **OIDC Login** (`/auth/login`), mounted by the plugin as usual. Both kinds of login end in the same session.

The plugin does not mount any passkey routes. This app adds three in [`src/index.ts`](./src/index.ts), and the page in [`public/`](./public) calls them. The [passkeys section of EXAMPLES.md](../../packages/auth0-fastify/EXAMPLES.md#login-and-signup-using-passkeys) explains each step.

## Before you start

You need an Auth0 tenant with:

1. **A [custom domain](https://auth0.com/docs/customize/custom-domains).** Passkeys are bound to it and do not work on `*.auth0.com`. Use it as `AUTH0_DOMAIN`.
2. **A Regular Web Application** with:
   - the **Client Secret** authentication method (starting a passkey flow does not accept a private key JWT or mTLS),
   - the **Passkey** grant turned on, under **Advanced Settings** > **Grant Types**,
   - `<APP_BASE_URL>/auth/callback` in **Allowed Callback URLs** and `<APP_BASE_URL>` in **Allowed Logout URLs** (for the OIDC login),
   - optionally **Trust Token Endpoint IP Header** turned on, under **Advanced Settings** > **OAuth**, so that Auth0 uses the user's IP address that this app forwards.
3. **A database connection with the Passkey authentication method**, under **Authentication Methods**, enabled for the application. Set `AUTH0_CONNECTION` to its name, or make it the tenant's Default Directory. To see the code inputs, turn on signup verification of the email address (with a code, not a link) and/or the phone number on the connection.
4. **A hostname for this app under your custom domain**, served over HTTPS. See [Where to run it](#where-to-run-it).

## Install dependencies

From the repository root:

```bash
npm install
npm run build
```

## Configuration

Rename `.env.example` to `.env` here and fill in the values:

| Variable | Value |
| --- | --- |
| `AUTH0_DOMAIN` | Your custom domain, for example `login.example.com`. |
| `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` | From the application. |
| `AUTH0_SESSION_SECRET` | The key that encrypts the session and passkey cookies. Generate one with `openssl rand -hex 64`. |
| `APP_BASE_URL` | The full address of this app, with `https://` (or `http://`), for example `https://app.login.example.com`. The page must be opened at exactly this address. |
| `AUTH0_CONNECTION` | The connection with the Passkey method. Optional: the Default Directory is used when it is empty. |
| `TRUST_PROXY` | The IP addresses or CIDR ranges of the reverse proxies in front of the app, comma separated, for example `127.0.0.1` or `10.0.0.0/8` (see below). Default `false`. Never `true` (a client could then choose its own IP address) or a number (current Fastify versions ignore it). |
| `PORT` | The port the app listens on. Default `3000`. |

## Where to run it

Auth0 uses your custom domain as the WebAuthn relying party ID, and a browser only lets a page use a passkey when the page is served over HTTPS from that domain or one of its subdomains. For the custom domain `login.example.com`, use a subdomain such as `https://app.login.example.com`. Auth0 serves the custom domain itself, so the app cannot be there. `http://localhost:3000` does not work: the browser refuses the passkey with a `SecurityError`.

To run it on your machine, with the hostname `app.login.example.com` (use a subdomain of your own custom domain):

1. Point the hostname at `127.0.0.1` with a `hosts` file entry: `127.0.0.1 app.login.example.com`.
2. Make a locally trusted certificate with [mkcert](https://github.com/FiloSottile/mkcert): run `mkcert -install` once, then `mkcert app.login.example.com`. It writes `app.login.example.com.pem` and `app.login.example.com-key.pem`.
3. Put a reverse proxy in front of the app. Any proxy works. With [Caddy](https://caddyserver.com), save this as `Caddyfile` next to the two certificate files, and start it with `caddy run`. It serves `https://app.login.example.com:8443` and forwards to the app on port 3000:

   ```
   {
     auto_https disable_redirects
   }

   app.login.example.com:8443 {
     bind 127.0.0.1
     tls app.login.example.com.pem app.login.example.com-key.pem
     reverse_proxy 127.0.0.1:3000
   }
   ```

4. In `.env`, set `APP_BASE_URL=https://app.login.example.com:8443` (the port is part of the address) and `TRUST_PROXY=loopback`, so that the app takes the user's IP address from the proxy on your machine (it connects from `127.0.0.1` or `::1`).

## Run

```bash
# in examples/example-fastify-web-passkeys
npm start
```

Open `APP_BASE_URL` in your browser.

## What to try

1. **Passkey Signup** with an email address. If the connection verifies emails, enter the code from the email, then create the passkey in the browser prompt.
2. **Passkey Signup** with an email address and a phone number. Enter a wrong phone code: only the phone input comes back, and the passkey prompt does not appear again. Then enter the right code.
3. **Send new codes** before the passkey is created, then enter the newest codes.
4. **Passkey Login** with the passkey you created. Log out and log in again.
5. Start a signup, then a passkey login in another tab. Finishing the signup asks you to start again, because the newer flow replaced it.

## How it works

| File | What it does |
| --- | --- |
| [`src/index.ts`](./src/index.ts) | Registers the plugin and adds the routes `POST /api/passkey/signup/start`, `/api/passkey/login/start` and `/api/passkey/complete`, plus `GET /api/session`. Also sets the security headers, the `Origin` check, the rate limits and a small body limit. |
| [`src/passkey.ts`](./src/passkey.ts) | The request schemas, and `completeFailure()`, which maps each error of `passkey.complete()` to the status the page acts on. |
| [`public/webauthn.js`](./public/webauthn.js) | The WebAuthn helpers: base64url decoding of the options, and serializing the credential. |
| [`public/app.js`](./public/app.js) | The page: the buttons, the code inputs for `verificationRequired`, and every status of `complete`. |

The browser never sees the Auth0 `authSession`. The SDK keeps it in the encrypted `HttpOnly` cookie `__a0_passkey_tx` between the start and the complete request.

> [!NOTE]
> This example shows Auth0's error messages on the page to help you while testing. In a real app, show a generic message and log the details.

## Troubleshooting

| What you see | Why, and what to do |
| --- | --- |
| The server stops with `Missing environment variables` | Copy `.env.example` to `.env` and fill in every value. |
| `403` with `This request must come from the app's own page` | The page was not opened at `APP_BASE_URL`. Use that exact address (scheme, host and port). |
| `The browser refused the passkey: the page origin does not fit its RP ID` | The page is not served over HTTPS from your custom domain or one of its subdomains. See [Where to run it](#where-to-run-it). |
| This browser does not support passkeys | The page is not in a secure context (HTTPS), or the browser has no WebAuthn. |
| The signup or login does not start, with a message from Auth0 | Check that the connection has the Passkey method turned on and is enabled for the application, that `AUTH0_CONNECTION` is its name (or it is the Default Directory), that `AUTH0_DOMAIN` is the custom domain, and that the application uses the Client Secret method. |
| The passkey prompt works, but finishing fails with a message from Auth0 | Turn on the **Passkey** grant for the application. |
| `This signup is over` or `This login is over` | The flow expired (Auth0 currently allows 60 seconds, or 15 minutes when codes are needed), or a newer passkey flow started in another tab. Start again. |
| `Auth0 is rate limiting these requests` | Wait as told, then use **Try again**. |
| `Too many requests` | This app's own rate limit (per IP address and minute: 5 signup starts, 30 login starts, 30 completions). Wait as told, then use **Try again**. The flow is kept. |
| `MFA` message after the passkey was accepted | The user must complete MFA, which this example does not include. |

## Tests

```bash
npm test
```

The tests run against a fake Auth0 (no tenant needed): the routes, the page and its headers, every `complete` status, the rate limits and the IP forwarding, and the WebAuthn helpers. `src/docs.spec.ts` also checks the code of the SDK's EXAMPLES.md against this example, so it needs this repository: delete it in a copy of the example. The page script `public/app.js` has no automated test here, so walk through [What to try](#what-to-try) after you change it.
