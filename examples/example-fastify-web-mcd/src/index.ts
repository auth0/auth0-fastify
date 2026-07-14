import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import fastifyAuth0, { DomainResolver } from '@auth0/auth0-fastify';
import type { StoreOptions } from '@auth0/auth0-fastify';
import ejs from 'ejs';
import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const fastify = Fastify({
  logger: true,
});

// Fix to use __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// Multiple Custom Domains (MCD) configuration.
//
// This single app serves two hostnames — brand-a.localhost and
// brand-b.localhost — on the same port, each mapped to a different Auth0
// custom domain of the SAME Auth0 tenant. The mapping is driven by env vars so
// you can point it at your own custom domains.
const defaultAuth0Domain = process.env.AUTH0_DOMAIN as string;
const domainsByHost: Record<string, string> = {
  'brand-a.localhost:3000': process.env.AUTH0_CUSTOM_DOMAIN_1 as string,
  'brand-b.localhost:3000': process.env.AUTH0_CUSTOM_DOMAIN_2 as string,
};

// Resolve the Auth0 custom domain for a given request host, falling back to the
// default domain when the host is not in the map.
//
// SECURITY: you are responsible for ensuring every resolved domain is a trusted
// custom domain of your Auth0 tenant. A resolver that returns an
// attacker-controlled value is a critical risk (auth bypass / SSRF). When
// inferring the host from request headers, run behind a trusted reverse proxy
// that sanitizes `Host` / `X-Forwarded-Host` before they reach the app.
function resolveAuth0Domain(host: string | undefined): string {
  return (host && domainsByHost[host]) || defaultAuth0Domain;
}

// A `DomainResolver` is called per request and receives the same per-request
// `StoreOptions` ({ request, reply }) the plugin passes internally to
// `auth0-server-js`. Passing it to `domain` (instead of a static string)
// enables MCD.
const domainResolver: DomainResolver<StoreOptions> = (storeOptions) =>
  resolveAuth0Domain(storeOptions?.request.headers.host);

// Register the Auth0 plugin in resolver mode.
//
// `domain` is the resolver function rather than a static string. `appBaseUrl`
// is intentionally omitted: in resolver mode the SDK infers the base URL from
// each request's host/proto headers, so callbacks, redirects, and logout use
// the correct origin per host. Make sure every served origin is registered in
// Auth0 as an Allowed Callback URL and Allowed Logout URL.
fastify.register(fastifyAuth0, {
  domain: domainResolver,
  clientId: process.env.AUTH0_CLIENT_ID as string,
  clientSecret: process.env.AUTH0_CLIENT_SECRET as string,
  sessionSecret: process.env.AUTH0_SESSION_SECRET as string,
  // Discovery (OIDC metadata + JWKS) is cached per resolved domain. Raise
  // `maxEntries` when a single process serves more than ~100 distinct Auth0
  // domains within the TTL window, which is common in larger MCD fleets.
  discoveryCache: { ttl: 600, maxEntries: 100 },
});

fastify.get('/', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });

  return reply.viewAsync('index.ejs', {
    isLoggedIn: !!user,
    user,
    host: request.headers.host,
    auth0Domain: resolveAuth0Domain(request.headers.host),
  });
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
    host: request.headers.host,
    auth0Domain: resolveAuth0Domain(request.headers.host),
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
      host: request.headers.host,
      auth0Domain: resolveAuth0Domain(request.headers.host),
    });
  }
);

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
    fastify.log.info('Server listening on http://brand-a.localhost:3000 and http://brand-b.localhost:3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

// Start the server only when this file is run directly (e.g. `npm start`), not
// when it is imported (e.g. by the test suite, which drives `fastify` via
// `fastify.inject`).
if (process.argv[1] === __filename) {
  start();
}
