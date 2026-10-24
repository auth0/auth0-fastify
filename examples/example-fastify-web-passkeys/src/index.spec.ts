import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { SignJWT, generateKeyPair } from 'jose';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './index.js';

// Env must be set BEFORE building the app (the plugin reads process.env when it is registered). The values are
// placeholders; the network is fully mocked below.
const DOMAIN = 'tenant.auth0.local';
const BASE = `https://${DOMAIN}`;
const CLIENT_ID = '<client_id>';
const CONNECTION = 'Username-Password-Authentication';
const ORIGIN = 'http://localhost:3000';

process.env.AUTH0_DOMAIN = DOMAIN;
process.env.AUTH0_CLIENT_ID = CLIENT_ID;
process.env.AUTH0_CLIENT_SECRET = '<client_secret>';
process.env.AUTH0_SESSION_SECRET = 'a-session-secret-of-at-least-32-characters-long';
process.env.APP_BASE_URL = ORIGIN;

// ─── A fake Auth0 that records what the app sends ─────────────────────────────────────────────

interface Call {
  body: Record<string, unknown>;
  headers: Headers;
}

const calls = { register: [] as Call[], challenge: [] as Call[], token: [] as Call[] };
let verificationRequired: string[] | undefined;
let tokenReplies: Array<() => Response | Promise<Response>> = [];

const { privateKey } = await generateKeyPair('RS256');
const idToken = () =>
  new SignJWT({ name: 'Jane Doe', email: 'jane@example.com', email_verified: true })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(`${BASE}/`)
    .setAudience(CLIENT_ID)
    .setSubject('auth0|user_123')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

const record = async (list: Call[], request: Request) => {
  list.push({ body: (await request.json()) as Record<string, unknown>, headers: request.headers });
};

const server = setupServer(
  http.get(`${BASE}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: `${BASE}/`,
      authorization_endpoint: `${BASE}/authorize`,
      token_endpoint: `${BASE}/oauth/token`,
      end_session_endpoint: `${BASE}/oidc/logout`,
    })
  ),
  http.post(`${BASE}/passkey/register`, async ({ request }) => {
    await record(calls.register, request);
    return HttpResponse.json({
      auth_session: 'auth-session-signup',
      authn_params_public_key: {
        challenge: 'c2lnbnVwLWNoYWxsZW5nZQ',
        rp: { id: DOMAIN, name: DOMAIN },
        user: { id: 'dXNlci1oYW5kbGU', name: 'jane@example.com', displayName: 'Jane' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: verificationRequired ? 900000 : 60000,
      },
      ...(verificationRequired && { verification_required: verificationRequired }),
    });
  }),
  http.post(`${BASE}/passkey/challenge`, async ({ request }) => {
    await record(calls.challenge, request);
    return HttpResponse.json({
      auth_session: 'auth-session-login',
      authn_params_public_key: { challenge: 'bG9naW4tY2hhbGxlbmdl', rpId: DOMAIN, timeout: 60000 },
    });
  }),
  http.post(`${BASE}/oauth/token`, async ({ request }) => {
    await record(calls.token, request);
    const reply = tokenReplies.shift();
    if (reply) {
      return reply();
    }
    return HttpResponse.json({
      access_token: 'access-token',
      id_token: await idToken(),
      expires_in: 3600,
      token_type: 'Bearer',
    });
  })
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
beforeEach(() => {
  // A developer's .env must not change the tests.
  process.env.AUTH0_CONNECTION = CONNECTION;
  process.env.TRUST_PROXY = 'false';
  process.env.APP_BASE_URL = ORIGIN;
});
afterEach(() => {
  server.resetHandlers();
  verificationRequired = undefined;
  tokenReplies = [];
  calls.register.length = 0;
  calls.challenge.length = 0;
  calls.token.length = 0;
});

// ─── Helpers ──────────────────────────────────────────────────────────────────────────────────

const clientData = (type: 'webauthn.create' | 'webauthn.get', challenge: string) =>
  Buffer.from(JSON.stringify({ type, challenge, origin: ORIGIN })).toString('base64url');

const signupCredential = {
  id: 'cred-id',
  rawId: 'cred-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: clientData('webauthn.create', 'c2lnbnVwLWNoYWxsZW5nZQ'),
    attestationObject: 'YXR0ZXN0YXRpb24',
  },
  clientExtensionResults: {},
};

const loginCredential = {
  id: 'cred-id',
  rawId: 'cred-id',
  type: 'public-key',
  response: {
    clientDataJSON: clientData('webauthn.get', 'bG9naW4tY2hhbGxlbmdl'),
    authenticatorData: 'YQ',
    signature: 'Yg',
    userHandle: 'Yw',
  },
};

type Res = { headers: Record<string, unknown> };

const setCookies = (res: Res): string[] => {
  const value = res.headers['set-cookie'];
  return Array.isArray(value) ? (value as string[]) : value ? [value as string] : [];
};

/** What a browser sends back: one cookie per name, the newest Set-Cookie wins, an expired cookie is dropped. */
function jar(...responses: Res[]): string {
  const cookies = new Map<string, string>();
  for (const res of responses) {
    for (const cookie of setCookies(res)) {
      const [pair = ''] = cookie.split(';');
      const [name = '', ...rest] = pair.split('=');
      if (rest.join('=') === '') {
        cookies.delete(name);
      } else {
        cookies.set(name, pair);
      }
    }
  }
  return [...cookies.values()].join('; ');
}

/** POSTs JSON the way the page does: from the app's own origin. */
const post = (
  app: FastifyInstance,
  url: string,
  payload: unknown = {},
  cookie?: string,
  headers: Record<string, string> = {}
) =>
  app.inject({
    method: 'POST',
    url,
    payload: JSON.stringify(payload),
    headers: { 'content-type': 'application/json', origin: ORIGIN, ...(cookie && { cookie }), ...headers },
  });

/** The credential Auth0 received in the latest token request. */
const sentCredential = () =>
  calls.token.at(-1)?.body.authn_response as { response: Record<string, unknown> } & Record<string, unknown>;

// ─── The page and the session ─────────────────────────────────────────────────────────────────

describe('the page', () => {
  test('is served with security headers', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/' });

    expect(res.statusCode).toBe(200);
    for (const id of ['passkey-login', 'passkey-signup', 'oidc-login']) {
      expect(res.body).toContain(`id="${id}"`);
    }
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test.each([
    ['/app.js', /javascript/, /passkey\/complete/],
    ['/webauthn.js', /javascript/, /export function serialize/],
    ['/style.css', /css/, /\.card/],
  ])('serves %s', async (url, contentType, content) => {
    const res = await (await buildApp()).inject({ method: 'GET', url });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(contentType);
    expect(res.body).toMatch(content);
  });

  test('has no user without a session, and the answer is never cached', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/api/session' });

    expect(res.json()).toEqual({ user: null });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  test('the OIDC login route of the plugin still redirects to Universal Login', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/auth/login' });

    expect(res.statusCode).toBe(302);
    expect(new URL(String(res.headers.location)).pathname).toBe('/authorize');
  });
});

describe('the configuration', () => {
  test('names the environment variables that are missing', async () => {
    delete process.env.AUTH0_CLIENT_SECRET;
    try {
      await expect(buildApp()).rejects.toThrow(/AUTH0_CLIENT_SECRET.*\.env\.example/);
    } finally {
      process.env.AUTH0_CLIENT_SECRET = '<client_secret>';
    }
  });

  test('explains an APP_BASE_URL that is not a URL', async () => {
    process.env.APP_BASE_URL = 'login.example.com';

    await expect(buildApp()).rejects.toThrow(/APP_BASE_URL must be a full URL/);
  });

  test('uses the default connection when AUTH0_CONNECTION is empty', async () => {
    process.env.AUTH0_CONNECTION = '';
    await post(await buildApp(), '/api/passkey/login/start');

    expect(calls.challenge[0]?.body).not.toHaveProperty('realm');
  });
});

// ─── Who may call the routes ──────────────────────────────────────────────────────────────────

test.each([
  ['no Origin header', {}],
  ['another origin', { origin: 'https://evil.example' }],
])('a POST with %s is refused before it reaches Auth0', async (_label, headers) => {
  const app = await buildApp();
  const res = await app.inject({
    method: 'POST',
    url: '/api/passkey/signup/start',
    payload: JSON.stringify({ email: 'jane@example.com' }),
    headers: { 'content-type': 'application/json', ...headers },
  });

  expect(res.statusCode).toBe(403);
  expect(res.json().status).toBe('forbidden');
  expect(calls.register).toHaveLength(0);
});

test('the Origin check follows the matched route, so a percent-encoded path does not slip past it', async () => {
  const app = await buildApp();
  const res = await app.inject({
    method: 'POST',
    url: '/%61pi/passkey/login/start', // the router decodes it to /api/passkey/login/start
    payload: '{}',
    headers: { 'content-type': 'text/plain' }, // what a cross-site form can send without a preflight
  });

  expect(res.statusCode).toBe(403);
  expect(calls.challenge).toHaveLength(0);
});

test('the no-store rule follows the matched route too', async () => {
  const res = await (await buildApp()).inject({ method: 'GET', url: '/%61pi/session' });

  expect(res.statusCode).toBe(200);
  expect(res.headers['cache-control']).toBe('no-store');
});

// ─── Starting a signup or a login ─────────────────────────────────────────────────────────────

describe('signup start', () => {
  test.each([
    ['nothing', {}],
    ['only a name', { name: 'Jane' }],
    ['a bad email address', { email: 'not-an-email' }],
    ['a phone number that is not E.164', { phoneNumber: '12345' }],
    ['an unknown delivery method', { email: 'jane@example.com', deliveryMethod: 'pigeon' }],
  ])('refuses %s with status invalid, without calling Auth0', async (_label, body) => {
    const res = await post(await buildApp(), '/api/passkey/signup/start', body);

    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ status: 'invalid', message: expect.any(String) });
    expect(calls.register).toHaveLength(0);
  });

  test('refuses a text/plain body, which a cross-site page could send without a preflight', async () => {
    const app = await buildApp();
    const res = await app.inject({
      method: 'POST',
      url: '/api/passkey/signup/start',
      payload: '{"email":"jane@example.com"}',
      headers: { 'content-type': 'text/plain', origin: ORIGIN },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().status).toBe('invalid');
    expect(calls.register).toHaveLength(0);
  });

  test('sends only the fields the browser may choose, and takes the connection from the server', async () => {
    await post(await buildApp(), '/api/passkey/signup/start', {
      email: 'jane@example.com',
      name: 'Jane',
      realm: 'evil-connection',
      organization: 'org_evil',
      userMetadata: { role: 'admin' },
      picture: 'https://evil.example/x.png',
    });

    const [register] = calls.register;
    expect(register?.body.realm).toBe(CONNECTION);
    expect(register?.body.user_profile).toEqual({ email: 'jane@example.com', name: 'Jane' });
    expect(JSON.stringify(register?.body)).not.toMatch(/org_evil|admin|evil\.example/);
  });

  test('returns the WebAuthn options and the identifiers to verify, and keeps the authSession from the browser', async () => {
    verificationRequired = ['email', 'phone'];
    const res = await post(await buildApp(), '/api/passkey/signup/start', {
      email: 'jane@example.com',
      phoneNumber: '+14155550100',
      deliveryMethod: 'voice',
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      authnParamsPublicKey: { challenge: 'c2lnbnVwLWNoYWxsZW5nZQ' },
      verificationRequired: ['email', 'phone'],
    });
    expect(res.body).not.toMatch(/auth.?session/i);
    expect(setCookies(res).join('\n')).toMatch(/__a0_passkey_tx=.*HttpOnly/);
    expect(calls.register[0]?.body.delivery_method).toBe('voice');
  });

  test('is rate limited per IP address', async () => {
    const app = await buildApp();
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      statuses.push((await post(app, '/api/passkey/signup/start', { email: 'jane@example.com' })).statusCode);
    }
    const limited = await post(app, '/api/passkey/signup/start', { email: 'jane@example.com' });

    expect(statuses).toEqual([200, 200, 200, 200, 200, 429]);
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({ status: 'rate_limited', message: expect.any(String) });
    expect(limited.headers['retry-after']).toBeDefined();
    expect(calls.register).toHaveLength(5);
  });

  test.each([
    [400, 'error'],
    [429, 'rate_limited'],
  ])('maps a %s from Auth0 to status %s', async (status, expected) => {
    server.use(
      http.post(`${BASE}/passkey/register`, () =>
        HttpResponse.json({ error: 'invalid_request', error_description: 'The user already exists.' }, { status })
      )
    );
    const res = await post(await buildApp(), '/api/passkey/signup/start', { email: 'jane@example.com' });

    expect(res.statusCode).toBe(status);
    expect(res.json()).toMatchObject({
      status: expected,
      message: expect.stringContaining('The user already exists.'),
    });
    expect(setCookies(res).join('\n')).not.toContain('__a0_passkey_tx');
  });
});

describe('login start', () => {
  test('returns the WebAuthn options and asks Auth0 on the connection', async () => {
    const res = await post(await buildApp(), '/api/passkey/login/start');

    expect(res.json()).toMatchObject({ authnParamsPublicKey: { rpId: DOMAIN } });
    expect(calls.challenge[0]?.body.realm).toBe(CONNECTION);
  });

  test('maps an Auth0 error to status error', async () => {
    server.use(
      http.post(`${BASE}/passkey/challenge`, () =>
        HttpResponse.json(
          { error: 'passkeys_not_enabled', error_description: 'Passkeys are not enabled.' },
          { status: 400 }
        )
      )
    );
    const res = await post(await buildApp(), '/api/passkey/login/start');

    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({
      status: 'error',
      message: expect.stringContaining('Passkeys are not enabled.'),
    });
  });
});

// ─── Completing ───────────────────────────────────────────────────────────────────────────────

describe('complete', () => {
  test('a signup without codes creates the session', async () => {
    const app = await buildApp();
    const start = await post(app, '/api/passkey/signup/start', { email: 'jane@example.com', name: 'Jane' });
    const done = await post(app, '/api/passkey/complete', { credential: signupCredential }, jar(start));

    expect(done.json()).toEqual({ status: 'complete' });

    const session = await app.inject({ method: 'GET', url: '/api/session', headers: { cookie: jar(start, done) } });
    expect(session.json().user).toMatchObject({ sub: 'auth0|user_123', name: 'Jane Doe', email: 'jane@example.com' });
    expect(session.body).not.toMatch(/access-token/);
  });

  test('a signup with codes: a wrong phone code asks again for the phone only, with the same passkey', async () => {
    verificationRequired = ['email', 'phone'];
    const app = await buildApp();
    const start = await post(app, '/api/passkey/signup/start', {
      email: 'jane@example.com',
      phoneNumber: '+14155550100',
    });
    tokenReplies.push(() =>
      HttpResponse.json(
        {
          error: 'invalid_grant',
          error_description: 'Invalid or expired session',
          auth_session: 'auth-session-signup',
          verification_required: ['phone'],
        },
        { status: 400 }
      )
    );

    const wrong = await post(
      app,
      '/api/passkey/complete',
      { credential: signupCredential, verification: { email: '123456', phone: '000000' } },
      jar(start)
    );
    expect(wrong.statusCode).toBe(400);
    expect(wrong.json()).toEqual({ status: 'retry', verificationRequired: ['phone'] });

    const retry = await post(
      app,
      '/api/passkey/complete',
      { credential: signupCredential, verification: { phone: '654321' } },
      jar(start, wrong)
    );
    expect(retry.json()).toEqual({ status: 'complete' });
    expect(calls.token.map((call) => call.body.verification)).toEqual([
      { email: '123456', phone: '000000' },
      { phone: '654321' },
    ]);
    expect(calls.token[1]?.body.authn_response).toEqual(calls.token[0]?.body.authn_response);
  });

  test('a login creates the session', async () => {
    const app = await buildApp();
    const start = await post(app, '/api/passkey/login/start');
    const done = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));

    expect(done.json()).toEqual({ status: 'complete' });
    expect(calls.token[0]?.body.auth_session).toBe('auth-session-login');
  });

  test('sends Auth0 only the credential fields it accepts', async () => {
    const app = await buildApp();
    const start = await post(app, '/api/passkey/signup/start', { email: 'jane@example.com' });
    await post(
      app,
      '/api/passkey/complete',
      {
        credential: {
          ...signupCredential,
          toJSON: 'x',
          extra: 1,
          response: { ...signupCredential.response, transports: ['internal'], publicKeyAlgorithm: -7 },
        },
        extraField: true,
      },
      jar(start)
    );

    expect(Object.keys(sentCredential()).sort()).toEqual([
      'authenticatorAttachment',
      'clientExtensionResults',
      'id',
      'rawId',
      'response',
      'type',
    ]);
    expect(Object.keys(sentCredential().response).sort()).toEqual(['attestationObject', 'clientDataJSON']);
  });

  test.each([
    ['no body fields', {}],
    [
      'a credential without rawId',
      { credential: { id: 'x', type: 'public-key', response: { clientDataJSON: 'e30' } } },
    ],
    ['a code that is too long', { credential: signupCredential, verification: { email: '12345678901' } }],
    [
      'a clientDataJSON that is not base64url JSON',
      { credential: { ...signupCredential, response: { clientDataJSON: 'not json' } } },
    ],
  ])('refuses %s with status invalid, without calling Auth0', async (_label, body) => {
    const res = await post(await buildApp(), '/api/passkey/complete', body);

    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ status: 'invalid' });
    expect(calls.token).toHaveLength(0);
  });

  test('drops a code for an identifier other than email and phone', async () => {
    verificationRequired = ['email'];
    const app = await buildApp();
    const start = await post(app, '/api/passkey/signup/start', { email: 'jane@example.com' });

    await post(
      app,
      '/api/passkey/complete',
      { credential: signupCredential, verification: { email: '123456', sms: '999999' } },
      jar(start)
    );

    expect(calls.token[0]?.body.verification).toEqual({ email: '123456' });
  });

  test('answers wait with the time Auth0 gave, and keeps the flow so the same request can be sent again', async () => {
    const app = await buildApp();
    const start = await post(app, '/api/passkey/login/start');
    tokenReplies.push(() =>
      HttpResponse.json(
        { error: 'too_many_requests', error_description: 'Slow down' },
        { status: 429, headers: { 'retry-after': '7' } }
      )
    );

    const limited = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));
    expect([limited.statusCode, limited.json()]).toEqual([429, { status: 'wait', retryAfterSeconds: 7 }]);

    const again = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start, limited));
    expect(again.json()).toEqual({ status: 'complete' });
  });

  test('answers mfa_required without leaking the mfa_token', async () => {
    const app = await buildApp();
    const start = await post(app, '/api/passkey/login/start');
    tokenReplies.push(() =>
      HttpResponse.json(
        { error: 'mfa_required', error_description: 'MFA required', mfa_token: 'secret-mfa-token' },
        { status: 403 }
      )
    );

    const res = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));

    expect(res.json()).toEqual({ status: 'mfa_required' });
    expect(res.body + JSON.stringify(res.headers)).not.toContain('secret-mfa-token');
  });

  test('answers restart, without calling Auth0, when there is no flow', async () => {
    const res = await post(await buildApp(), '/api/passkey/complete', { credential: loginCredential });

    expect([res.statusCode, res.json()]).toEqual([400, { status: 'restart' }]);
    expect(calls.token).toHaveLength(0);
  });

  test('answers invalid for a missing code, keeps the flow, and then completes with the code', async () => {
    verificationRequired = ['email'];
    const app = await buildApp();
    const start = await post(app, '/api/passkey/signup/start', { email: 'jane@example.com' });

    const missing = await post(app, '/api/passkey/complete', { credential: signupCredential }, jar(start));
    expect(missing.json()).toMatchObject({ status: 'invalid' });
    expect(calls.token).toHaveLength(0);

    const done = await post(
      app,
      '/api/passkey/complete',
      { credential: signupCredential, verification: { email: '123456' } },
      jar(start, missing)
    );
    expect(done.json()).toEqual({ status: 'complete' });
  });

  test('answers failed when Auth0 refuses the exchange, with Auth0\'s reason', async () => {
    const app = await buildApp();
    const start = await post(app, '/api/passkey/login/start');
    tokenReplies.push(() =>
      HttpResponse.json({ error: 'access_denied', error_description: 'Unauthorized' }, { status: 403 })
    );

    const res = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));

    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ status: 'failed', message: 'Unauthorized (access_denied)' });
  });

  test('answers failed when Auth0 cannot be reached, and keeps the flow so the same request can be sent again', async () => {
    const app = await buildApp();
    const start = await post(app, '/api/passkey/login/start');
    tokenReplies.push(() => HttpResponse.error());

    const failed = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));
    expect(failed.statusCode).toBe(400);
    expect(failed.json()).toMatchObject({ status: 'failed', message: expect.stringContaining('Failed to fetch') });

    const again = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start, failed));
    expect(again.json()).toEqual({ status: 'complete' });
  });
});

// ─── The user's IP address ────────────────────────────────────────────────────────────────────

describe('the user IP address', () => {
  test('is not trusted from X-Forwarded-For by default', async () => {
    await post(await buildApp(), '/api/passkey/login/start', {}, undefined, { 'x-forwarded-for': '203.0.113.9' });

    expect(calls.challenge[0]?.headers.get('auth0-forwarded-for')).toBe('127.0.0.1');
  });

  test('is the address the proxy added when TRUST_PROXY is the number of proxies, not one the client chose', async () => {
    process.env.TRUST_PROXY = '1';
    // The client sent 198.51.100.99 itself. The one proxy in front of the app appended the address it saw.
    await post(await buildApp(), '/api/passkey/login/start', {}, undefined, {
      'x-forwarded-for': '198.51.100.99, 203.0.113.9',
    });

    expect(calls.challenge[0]?.headers.get('auth0-forwarded-for')).toBe('203.0.113.9');
  });

  test.each(['true', 'yes', '1.5', '-1', '1,2'])('refuses TRUST_PROXY=%s and explains it', async (value) => {
    process.env.TRUST_PROXY = value;

    await expect(buildApp()).rejects.toThrow(/TRUST_PROXY must be the number of .*proxies/);
  });

  test('sends no header when the address is unknown, instead of the text "undefined"', async () => {
    const app = await buildApp();
    app.addHook('onRequest', async (request) => {
      // A server on a unix socket has no remote address.
      Object.defineProperty(request.raw.socket, 'remoteAddress', { value: undefined, configurable: true });
    });
    await post(app, '/api/passkey/login/start');

    expect(calls.challenge).toHaveLength(1);
    expect(calls.challenge[0]?.headers.has('auth0-forwarded-for')).toBe(false);
  });
});

// ─── Every route that calls Auth0 is limited and small ────────────────────────────────────────

describe('abuse limits', () => {
  test.each([
    ['/api/passkey/login/start', {}, 30],
    ['/api/passkey/complete', { credential: loginCredential }, 30],
  ])('%s is rate limited per IP address', async (url, payload, max) => {
    const app = await buildApp();
    const statuses: number[] = [];
    for (let i = 0; i <= max; i++) {
      statuses.push((await post(app, url, payload)).statusCode);
    }

    expect(statuses.slice(0, max)).not.toContain(429);
    expect(statuses[max]).toBe(429);
  });

  test('each route is counted on its own', async () => {
    const app = await buildApp();
    for (let i = 0; i < 30; i++) {
      await post(app, '/api/passkey/login/start');
    }
    const signup = await post(app, '/api/passkey/signup/start', { email: 'jane@example.com' });

    expect(signup.statusCode).toBe(200);
  });

  test.each(['/api/passkey/signup/start', '/api/passkey/login/start', '/api/passkey/complete'])(
    '%s refuses a body that no credential needs to be as big as',
    async (url) => {
      const res = await post(await buildApp(), url, { email: 'jane@example.com', padding: 'x'.repeat(40_000) });

      expect(res.statusCode).toBe(413);
      expect(calls.register).toHaveLength(0);
    }
  );
});
