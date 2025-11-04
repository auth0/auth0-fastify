import Fastify, { FastifyReply, FastifyRequest, RouteGenericInterface } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import fastifyAuth0 from '@auth0/auth0-fastify';
import ejs from 'ejs';
import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { Http2SecureServer, Http2ServerRequest, Http2ServerResponse } from 'node:http2';

const fastify = Fastify({
  logger: true,
  http2: true,

  // Use `mkcert localhost 127.0.0.1 ::1` in the `examples/example-fastify-web` directory to generate these files
  https: {
    allowHTTP1: true,
    key: readFileSync('./localhost+2-key.pem'),
    cert: readFileSync('./localhost+2.pem')
  }
});

// Fix to use __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename); 

fastify.register(fastifyStatic, {
  root: path.join(__dirname, '../public')
});

fastify.register(fastifyView, {
  engine: {
    ejs: ejs,
  },
  root: './views',
  layout: 'layout.ejs',
});

fastify.register(fastifyAuth0, {
  domain: process.env.AUTH0_DOMAIN as string,
  clientId: process.env.AUTH0_CLIENT_ID as string,
  clientSecret: process.env.AUTH0_CLIENT_SECRET as string,
  appBaseUrl: process.env.APP_BASE_URL as string,
  sessionSecret: process.env.AUTH0_SESSION_SECRET as string,
});


fastify.get('/', async (request, reply) => {
  const user = await fastify.auth0Client!.getUser();

  return reply.viewAsync('index.ejs', { isLoggedIn: !!user, user: user });
});

async function hasSessionPreHandler(
  request: FastifyRequest<RouteGenericInterface, Http2SecureServer, Http2ServerRequest>,
  reply: FastifyReply<RouteGenericInterface, Http2SecureServer, Http2ServerRequest, Http2ServerResponse<Http2ServerRequest>>
) {
  const session = await fastify.auth0Client!.getSession();

  if (!session) {
    reply.redirect(`/auth/login?returnTo=${request.url}`);
  }
}

fastify.get(
  '/public',
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser();

    return reply.viewAsync('public.ejs', {
      isLoggedIn: !!user,
      user,
    });
  }
);

fastify.get(
  '/private',
  {
    preHandler: hasSessionPreHandler,
  },
  async (request, reply) => {
    const user = await fastify.auth0Client!.getUser();

    return reply.viewAsync('private.ejs', {
      isLoggedIn: !!user,
      user,
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
