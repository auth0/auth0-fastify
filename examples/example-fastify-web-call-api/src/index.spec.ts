import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import type { FastifyInstance } from 'fastify';

// Env must be set BEFORE building the app (the SDK reads process.env when the
// plugin is registered). The values are placeholders; the network is fully
// mocked below.
const AUTH0_DOMAIN = 'tenant.auth0.local';
const CLIENT_ID = '<client_id>';
const AUDIENCE = 'https://api.example.com';

process.env.AUTH0_DOMAIN = AUTH0_DOMAIN;
process.env.AUTH0_CLIENT_ID = CLIENT_ID;
process.env.AUTH0_CLIENT_SECRET = '<client_secret>';
process.env.AUTH0_SESSION_SECRET = 'a-session-secret-of-at-least-32-characters-long';
process.env.APP_BASE_URL = 'http://localhost:3000';
process.env.AUTH0_AUDIENCE = AUDIENCE;
process.env.API_BASE_URL = 'http://api.local';

const KID = 'test-key-1';
let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;

const discovery = {
  issuer: `https://${AUTH0_DOMAIN}/`,
  authorization_endpoint: `https://${AUTH0_DOMAIN}/authorize`,
  token_endpoint: `https://${AUTH0_DOMAIN}/oauth/token`,
  end_session_endpoint: `https://${AUTH0_DOMAIN}/logout`,
  jwks_uri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
};

const server = setupServer(
  http.get(`https://${AUTH0_DOMAIN}/.well-known/openid-configuration`, () => HttpResponse.json(discovery)),
  http.get(discovery.jwks_uri, () =>
    HttpResponse.json({ keys: [{ ...publicJwk, kid: KID, alg: 'RS256', use: 'sig' }] })
  ),
  http.post(discovery.token_endpoint, async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({ name: 'Jane Doe', email: 'jane@example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuer(discovery.issuer)
      .setAudience(CLIENT_ID)
      .setSubject('auth0|user_123')
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(privateKey);
    const accessToken = await new SignJWT({ scope: 'openid profile' })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuer(discovery.issuer)
      .setAudience(AUDIENCE)
      .setSubject('auth0|user_123')
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(privateKey);
    return HttpResponse.json({
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 3600,
    });
  }),
  // The downstream resource server (examples/example-fastify-api), mocked. Its
  // /api/private route returns plain text and requires a bearer token; here we
  // echo the subject only when a Bearer token is present so the test can assert
  // the token was forwarded.
  http.get('http://api.local/api/private', ({ request: req }) => {
    const auth = req.headers.get('authorization') ?? '';
    if (!auth.startsWith('Bearer ')) {
      return new HttpResponse('Unauthorized', { status: 401 });
    }
    return new HttpResponse('Hello, auth0|user_123');
  })
);

// Join Set-Cookie header(s) into a Cookie request header (name=value pairs).
const cookieHeader = (h: string | string[] | undefined) =>
  (Array.isArray(h) ? h : [h ?? '']).map((c) => c.split(';')[0]).join('; ');

let app: FastifyInstance;

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'bypass' });
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey as CryptoKey;
  publicJwk = await exportJWK(kp.publicKey);
  const { buildApp } = await import('./index.js');
  app = buildApp();
  await app.ready();
});

afterEach(() => server.resetHandlers());
afterAll(async () => {
  server.close();
  await app.close();
});

// Drives login -> callback and returns the session Cookie header.
async function login(): Promise<string> {
  const loginRes = await app.inject({ method: 'GET', url: '/auth/login' });
  expect(loginRes.statusCode).toBe(302);
  const txCookie = cookieHeader(loginRes.headers['set-cookie']);

  const cbRes = await app.inject({
    method: 'GET',
    url: '/auth/callback?code=fake-code',
    headers: { cookie: txCookie },
  });
  expect(cbRes.statusCode).toBe(302);
  return cookieHeader(cbRes.headers['set-cookie']);
}

describe('example-fastify-web-call-api', () => {
  test('login requests an access token for the configured audience', async () => {
    const res = await app.inject({ method: 'GET', url: '/auth/login' });
    const authorizeUrl = new URL(res.headers['location']?.toString() ?? '');

    expect(res.statusCode).toBe(302);
    expect(authorizeUrl.host).toBe(AUTH0_DOMAIN);
    expect(authorizeUrl.searchParams.get('audience')).toBe(AUDIENCE);
  });

  test('after login, /call-api forwards the access token and renders the API response', async () => {
    const sessionCookie = await login();

    const res = await app.inject({
      method: 'GET',
      url: '/call-api',
      headers: { cookie: sessionCookie },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Response from the API');
    expect(res.body).toContain('Hello, auth0|user_123');
  });

  test('/call-api redirects to login when there is no session', async () => {
    const res = await app.inject({ method: 'GET', url: '/call-api' });
    expect(res.statusCode).toBe(302);
    expect(res.headers['location']?.toString()).toContain('/auth/login');
  });
});
