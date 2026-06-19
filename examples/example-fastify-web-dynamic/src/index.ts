import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import fastifyAuth0 from '@auth0/auth0-fastify';
import ejs from 'ejs';
import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// `trustProxy: true` makes Fastify derive `request.host` / `request.protocol`
// from the `X-Forwarded-Host` / `X-Forwarded-Proto` headers your proxy sets.
// The SDK relies on those accessors to infer the application base URL per
// request, so this is required for dynamic and allow-list modes behind a proxy.
const fastify = Fastify({
  logger: true,
  trustProxy: true,
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

// `APP_BASE_URL` drives which mode this example runs in:
// - unset/empty           -> dynamic: the base URL is inferred from every request.
// - single URL            -> static: a fixed base URL (classic single-host setup).
// - comma-separated URLs  -> allow-list: inferred per request, but the origin must
//                            be one of the listed values or the request is rejected.
const parseAppBaseUrl = (value: string | undefined): string | string[] | undefined => {
  if (!value) {
    return undefined;
  }

  const entries = value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  if (entries.length === 0) {
    return undefined;
  }

  return entries.length === 1 ? entries[0] : entries;
};

const appBaseUrl = parseAppBaseUrl(process.env.APP_BASE_URL);

fastify.log.info(
  { appBaseUrl: appBaseUrl ?? '(inferred per request)' },
  'Configured appBaseUrl mode'
);

fastify.register(fastifyAuth0, {
  domain: process.env.AUTH0_DOMAIN as string,
  clientId: process.env.AUTH0_CLIENT_ID as string,
  clientSecret: process.env.AUTH0_CLIENT_SECRET as string,
  appBaseUrl,
  sessionSecret: process.env.AUTH0_SESSION_SECRET as string,
});

fastify.get('/', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser({ request, reply });

  return reply.viewAsync('index.ejs', {
    isLoggedIn: !!user,
    user: user,
    origin: `${request.protocol}://${request.host}`,
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
    origin: `${request.protocol}://${request.host}`,
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
      origin: `${request.protocol}://${request.host}`,
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
