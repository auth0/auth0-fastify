import Fastify, { type FastifyError, type FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import rateLimit from '@fastify/rate-limit';
import fastifyAuth0, { PasskeyChallengeError, PasskeyRegisterError } from '@auth0/auth0-fastify';
import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { completeBody, completeFailure, describeError, signupBody } from './passkey.js';
import type { CompleteBody, SignupBody } from './passkey.js';

// Fix to use __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REQUIRED_ENV = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET', 'AUTH0_SESSION_SECRET', 'APP_BASE_URL'];

// The number of reverse proxies in front of the app: 0 when it is reachable directly. Never "true": Fastify would then
// trust every X-Forwarded-For entry, so a client could choose the IP address that the rate limit counts and that Auth0
// receives. With a number, it trusts only the entries that your own proxies added.
function trustedProxies(value = ''): number {
  if (value === '' || value === 'false') {
    return 0;
  }
  const proxies = Number(value);
  if (!Number.isInteger(proxies) || proxies < 0) {
    throw new Error(
      `TRUST_PROXY must be the number of reverse proxies in front of this app, for example 1 (got "${value}"). ` +
        'Do not use "true": it trusts every X-Forwarded-For entry, so a client could choose its own IP address.'
    );
  }
  return proxies;
}

// Every passkey route calls Auth0 for anyone who can reach it, and the signup start also sends messages, so it gets the
// strictest limit. A credential is a few KB, so a small body limit keeps these routes cheap.
const limits = (max: number) => ({ bodyLimit: 32 * 1024, config: { rateLimit: { max, timeWindow: '1 minute' } } });

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "img-src 'self' https: data:",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

// Build the Fastify app. Exported so the test suite can drive it with
// `fastify.inject()` without binding a port. It is async because the rate limit
// plugin must be loaded before the routes that use it are defined.
export async function buildApp() {
  const missing = REQUIRED_ENV.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(
      `Missing environment variables: ${missing.join(', ')}. Copy .env.example to .env and fill them in.`
    );
  }

  const appBaseUrl = process.env.APP_BASE_URL as string;
  let appOrigin: string;
  try {
    appOrigin = new URL(appBaseUrl).origin;
  } catch {
    throw new Error(`APP_BASE_URL must be a full URL, for example https://login.example.com (got "${appBaseUrl}").`);
  }

  const fastify = Fastify({
    logger: process.env.NODE_ENV !== 'test',
    // Behind a reverse proxy you control, set TRUST_PROXY to their number (for example 1) so that `request.ip` is the
    // user's address and not the proxy's. Never trust X-Forwarded-For when the app is reachable directly.
    trustProxy: trustedProxies(process.env.TRUST_PROXY) || false,
  });

  // The database connection that has the Passkey authentication method turned on. It is set here, on the server:
  // the browser never chooses it. Without it, Auth0 uses the tenant's Default Directory.
  const realm = process.env.AUTH0_CONNECTION || undefined;

  fastify.addHook('onRequest', async (request, reply) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('content-security-policy', CONTENT_SECURITY_POLICY);

    // Decide by the route that matched, not by the raw URL: the router also matches a percent-encoded path such as
    // /%61pi/passkey/login/start, which `request.url` would not show as /api/.
    const route = request.routeOptions.url ?? '';
    if (route.startsWith('/api/') || route.startsWith('/auth/')) {
      reply.header('cache-control', 'no-store');
    }

    // The passkey routes write cookies, so they only accept requests from this app's own page. `fetch()` always sends
    // `Origin` with a POST, and a page on another site cannot fake it.
    if (request.method === 'POST' && route.startsWith('/api/') && request.headers.origin !== appOrigin) {
      return reply.code(403).send({
        status: 'forbidden',
        message: `This request must come from the app's own page: its Origin header must be ${appOrigin}.`,
      });
    }
  });

  // Errors the routes do not catch themselves: a body that the schema refused, the rate limit, and the passkey start
  // calls. Set it before the routes, so that every route uses it.
  fastify.setErrorHandler<FastifyError>((error, request, reply) => {
    if (error.validation) {
      return reply.code(400).send({ status: 'invalid', message: error.message });
    }
    if (error.statusCode === 429) {
      // From the rate limit below, or from Auth0 (a PasskeyRegisterError or PasskeyChallengeError).
      return reply.code(429).send({ status: 'rate_limited', message: describeError(error) });
    }
    if (error instanceof PasskeyRegisterError || error instanceof PasskeyChallengeError) {
      // Nothing was stored. Auth0 rejected the request, for example because the user exists or a code could not be
      // sent. A real app shows a generic message; this example shows Auth0's reason to help with testing.
      request.log.warn(`${request.method} ${request.url}: ${describeError(error)}`);
      return reply.code(400).send({ status: 'error', message: describeError(error) });
    }
    return reply.send(error);
  });

  fastify.register(fastifyStatic, {
    root: path.join(__dirname, '../public'),
  });

  // `global: false`: only the routes that ask for a limit get one. A server on a unix socket has no `request.ip`
  // unless a trusted proxy header sets it, and the default key generator fails on that: count those requests together
  // instead.
  await fastify.register(rateLimit, { global: false, keyGenerator: (request) => request.ip ?? 'unknown' });

  fastify.register(fastifyAuth0, {
    domain: process.env.AUTH0_DOMAIN as string,
    clientId: process.env.AUTH0_CLIENT_ID as string,
    clientSecret: process.env.AUTH0_CLIENT_SECRET as string,
    appBaseUrl,
    sessionSecret: process.env.AUTH0_SESSION_SECRET as string,
  });

  // Auth0 sees this server's address. This header tells it the user's address. Auth0 uses it only for applications
  // with "Trust Token Endpoint IP Header" turned on (Advanced Settings > OAuth).
  // A server on a unix socket has no remote address: then send no header, not the text "undefined".
  const forwardIp = (request: FastifyRequest) =>
    request.ip ? { headers: { 'auth0-forwarded-for': request.ip } } : undefined;

  // 1a. Start a signup. When the connection verifies the email address or phone number, Auth0 sends the codes now.
  //     Every call can send a message to any address or number, so this route is rate limited.
  fastify.post<{ Body: SignupBody }>(
    '/api/passkey/signup/start',
    { schema: { body: signupBody }, ...limits(5) },
    async (request, reply) => {
      const { authnParamsPublicKey, verificationRequired } = await fastify.auth0Client!.passkey.startSignup(
        { ...request.body, realm },
        { request, reply },
        forwardIp(request)
      );

      return { authnParamsPublicKey, verificationRequired: verificationRequired ?? [] };
    }
  );

  // 1b. Start a login.
  fastify.post('/api/passkey/login/start', limits(30), async (request, reply) => {
    const { authnParamsPublicKey } = await fastify.auth0Client!.passkey.startLogin(
      { realm },
      { request, reply },
      forwardIp(request)
    );

    return { authnParamsPublicKey };
  });

  // 2. Complete a signup or a login. The SDK reads the flow from its cookie, exchanges the passkey for tokens and
  //    writes the session.
  fastify.post<{ Body: CompleteBody }>(
    '/api/passkey/complete',
    { schema: { body: completeBody }, ...limits(30) },
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
        const { httpStatus, body } = completeFailure(error);
        if (body.status === 'failed') {
          // A summary, never the whole error: the `cause` of a passkey error can hold an `mfa_token`.
          request.log.warn(`passkey.complete() failed: ${body.message}`);
        }

        return reply.code(httpStatus).send(body);
      }
    }
  );

  // The user of the current session, or null. These are the profile claims, never the tokens.
  fastify.get('/api/session', async (request, reply) => {
    const user = await fastify.auth0Client!.getUser({ request, reply });

    return { user: user ?? null };
  });

  return fastify;
}

const start = async () => {
  try {
    const fastify = await buildApp();
    // Defaults to 3000; set PORT to run on another port.
    await fastify.listen({ port: Number(process.env.PORT) || 3000 });
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
};

// Start the server only when run directly (`npm start`), not when imported by
// the test suite (which drives the app via `fastify.inject()`).
if (process.argv[1] === __filename) {
  start();
}
