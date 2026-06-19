import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import type { FastifyInstance } from 'fastify';

// The app reads process.env at import time to build its appBaseUrl config and to
// register the plugin, so these must be set BEFORE importing it. We run the
// example in ALLOW-LIST mode: the base URL is inferred per request, but the
// inferred origin must be one of the listed values.
const DOMAIN = 'example.auth0.local';

// Under `fastify.inject` with `trustProxy` enabled, `request.host` comes from the
// `host` header and `request.protocol` defaults to `http`, so the inferred
// origin is `http://<host>`. The allow-list entries match that form.
const BRAND_1_ORIGIN = 'http://brand-1.localhost:3000';
const BRAND_2_ORIGIN = 'http://brand-2.localhost:3000';

process.env.AUTH0_DOMAIN = DOMAIN;
process.env.AUTH0_CLIENT_ID = '<client_id>';
process.env.AUTH0_CLIENT_SECRET = '<client_secret>';
process.env.AUTH0_SESSION_SECRET = '<a-session-secret-of-at-least-32-chars>';
process.env.APP_BASE_URL = `${BRAND_1_ORIGIN},${BRAND_2_ORIGIN}`;

// A minimal OIDC discovery document. /auth/login only needs the
// authorization_endpoint to build the 302, so that is all we mock.
const discoveryDocument = (domain: string) => ({
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  token_endpoint: `https://${domain}/oauth/token`,
  end_session_endpoint: `https://${domain}/logout`,
});

const server = setupServer(
  http.get(`https://${DOMAIN}/.well-known/openid-configuration`, () => HttpResponse.json(discoveryDocument(DOMAIN)))
);

let fastify: FastifyInstance;

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'bypass' });
  // Import after env is set so the module builds its appBaseUrl config correctly.
  // The start() call is guarded, so importing does not bind a port.
  ({ fastify } = await import('./index.js'));
  await fastify.ready();
});

afterEach(() => server.resetHandlers());
afterAll(async () => {
  server.close();
  await fastify.close();
});

describe('example-fastify-web-dynamic: per-host base URL resolution', () => {
  test('login from an allow-listed host infers that origin for the redirect_uri', async () => {
    const res = await fastify.inject({
      method: 'GET',
      url: '/auth/login',
      headers: { host: 'brand-1.localhost:3000' },
    });
    const location = new URL(res.headers['location']?.toString() ?? '');

    expect(res.statusCode).toBe(302);
    expect(location.host).toBe(DOMAIN);
    expect(location.pathname).toBe('/authorize');
    expect(location.searchParams.get('redirect_uri')).toBe(`${BRAND_1_ORIGIN}/auth/callback`);
  });

  test('login from a second allow-listed host infers that origin for the redirect_uri', async () => {
    const res = await fastify.inject({
      method: 'GET',
      url: '/auth/login',
      headers: { host: 'brand-2.localhost:3000' },
    });
    const location = new URL(res.headers['location']?.toString() ?? '');

    expect(res.statusCode).toBe(302);
    expect(location.host).toBe(DOMAIN);
    expect(location.pathname).toBe('/authorize');
    expect(location.searchParams.get('redirect_uri')).toBe(`${BRAND_2_ORIGIN}/auth/callback`);
  });

  test('login from a host not in the allow-list is rejected', async () => {
    const res = await fastify.inject({
      method: 'GET',
      url: '/auth/login',
      headers: { host: 'evil.localhost:3000' },
    });

    expect(res.statusCode).toBe(500);
  });
});
