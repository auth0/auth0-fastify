import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import fastifyAuth0 from '@auth0/auth0-fastify';
import ejs from 'ejs';
import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const fastify = Fastify({
  logger: true,
});

// Fix to use __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Base URL of the resource server this app calls on the user's behalf.
//
// This example calls a SEPARATE API service. The API example in this repo
// (examples/example-fastify-api) is a ready-made resource server protected by
// @auth0/auth0-fastify-api — run it alongside this app (see the README) and
// point API_BASE_URL at it.
const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:3001';

fastify.register(fastifyStatic, {
  root: path.join(__dirname, '../public'),
});

fastify.register(fastifyView, {
  engine: {
    ejs: ejs,
  },
  root: './views',
  layout: 'layout.ejs',
});

// Register the Auth0 plugin.
//
// Passing `audience` makes the SDK request an access token for that API when
// the user logs in. The token is then available via `getAccessToken()` and is
// used below to call the resource server on the user's behalf.
fastify.register(fastifyAuth0, {
  domain: process.env.AUTH0_DOMAIN as string,
  clientId: process.env.AUTH0_CLIENT_ID as string,
  clientSecret: process.env.AUTH0_CLIENT_SECRET as string,
  audience: process.env.AUTH0_AUDIENCE as string,
  appBaseUrl: process.env.APP_BASE_URL as string,
  sessionSecret: process.env.AUTH0_SESSION_SECRET as string,
});

fastify.get('/', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });

  return reply.viewAsync('index.ejs', { isLoggedIn: !!user, user: user });
});

async function hasSessionPreHandler(request: FastifyRequest, reply: FastifyReply) {
  const session = await fastify.auth0Client!.getSession({ request, reply });

  if (!session) {
    reply.redirect(`/auth/login?returnTo=${request.url}`);
  }
}

fastify.get('/public', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });

  return reply.viewAsync('public.ejs', {
    isLoggedIn: !!user,
    user,
  });
});

fastify.get(
  '/private',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });

    return reply.viewAsync('private.ejs', {
      isLoggedIn: !!user,
      user,
    });
  }
);

// Call the resource server on behalf of the logged-in user.
//
// 1. `getAccessToken()` returns an access token for the configured `audience`
//    (requesting/refreshing it as needed).
// 2. We call the API with the token in the `Authorization` header.
// 3. The API validates the token and returns data, which we render.
fastify.get(
  '/call-api',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });
    const { accessToken } = await fastify.auth0Client!.getAccessToken({ request, reply });

    const response = await fetch(`${apiBaseUrl}/api/private`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }

    const apiResponse = await response.text();

    return reply.viewAsync('api.ejs', {
      isLoggedIn: !!user,
      user,
      audience: process.env.AUTH0_AUDIENCE as string,
      apiResponse,
    });
  }
);

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
