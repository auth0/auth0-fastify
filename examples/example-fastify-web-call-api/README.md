# Fastify Web App Calling an API Example

This example shows how to use [`@auth0/auth0-fastify`](../../packages/auth0-fastify)
to log a user in, request an access token for an API (`audience`), and call a
resource server on the user's behalf.

The resource server is the existing [Fastify API example](../example-fastify-api)
in this repo, which is protected by
[`@auth0/auth0-fastify-api`](../../packages/auth0-fastify-api). You run it as a
separate service alongside this web app.

## Install dependencies

From the repository root:

```bash
npm install
npm run build
```

## Configuration

This example needs an Auth0 **Regular Web Application** (for the web app) and an
Auth0 **API** (the `audience`). Configure both this example and the
`example-fastify-api` to use the same API.

Rename `.env.example` to `.env` here and fill in the values:

```env
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_CLIENT_ID=YOUR_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_CLIENT_SECRET
AUTH0_SESSION_SECRET=A_LONG_RANDOM_SECRET
APP_BASE_URL=http://localhost:3000
AUTH0_AUDIENCE=YOUR_API_AUDIENCE
API_BASE_URL=http://localhost:3001
```

`AUTH0_AUDIENCE` must be the identifier of the API registered in your Auth0
tenant. The resource server validates tokens against this same audience.

The `AUTH0_SESSION_SECRET` is the key used to encrypt the session cookie. You
can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

> [!IMPORTANT]
> In the Auth0 Dashboard, add `http://localhost:3000/auth/callback` to **Allowed
> Callback URLs** and `http://localhost:3000` to **Allowed Logout URLs**.

## Run

Start the resource server (the API example) on port 3001 in one terminal:

```bash
# in examples/example-fastify-api (configure its .env with the same AUTH0_AUDIENCE)
PORT=3001 npm start
```

Start this web app on port 3000 in another terminal:

```bash
# in examples/example-fastify-web-call-api
npm start
```

Open http://localhost:3000, log in, then visit **Call API** (`/call-api`). The
web app requests an access token for `AUTH0_AUDIENCE` and calls
`GET /api/private` on the resource server with it, then renders the response.
