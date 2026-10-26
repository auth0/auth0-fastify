// Passkey login and signup through the plugin: the real cookie handler, and a fake Auth0 served by msw.
// The routes below are the ones in the "Login and Signup using Passkeys" section of EXAMPLES.md; the last test checks
// it. Many tests pin what @auth0/auth0-server-js does and what that section promises (when the flow is kept or
// deleted, which error comes for which case). If one fails after a server-js update, check that section too before
// changing the test.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, expect, test, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Fastify from 'fastify';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { StateData } from '@auth0/auth0-server-js';
import fastifyAuth0, {
  isMfaRequiredError,
  MissingRequiredArgumentError,
  MissingStoreOptionsError,
  MissingTransactionError,
  PasskeyChallengeError,
  PasskeyGetTokenError,
  PasskeyRegisterError,
  SessionExpiredError,
} from './index.js';
import * as sdk from './index.js';
import type {
  PasskeyApiErrorResponse,
  PasskeyChallengeOptions,
  PasskeyCompleteOptions,
  PasskeyCreationOptions,
  PasskeyCredentialResponse,
  PasskeyDeliveryMethod,
  PasskeyGetTokenApiErrorResponse,
  PasskeyGetTokenResult,
  PasskeyRegisterOptions,
  PasskeyRequestOptions,
  PasskeyStartLoginResult,
  PasskeyStartSignupResult,
  PasskeyVerificationCodes,
  PasskeyVerificationIdentifier,
  StoreOptions,
} from './index.js';
import { decrypt, encrypt } from './test-utils/encryption.js';
import { generateToken } from './test-utils/tokens.js';

// Compile-time check, run by `tsc --noEmit`: every type the docs mention is exported from the package root.
export type PasskeyTypesAreExported = [
  PasskeyApiErrorResponse,
  PasskeyChallengeOptions,
  PasskeyCompleteOptions,
  PasskeyCreationOptions,
  PasskeyCredentialResponse,
  PasskeyDeliveryMethod,
  PasskeyGetTokenApiErrorResponse,
  PasskeyGetTokenResult,
  PasskeyRegisterOptions,
  PasskeyRequestOptions,
  PasskeyStartLoginResult,
  PasskeyStartSignupResult,
  PasskeyVerificationCodes,
  PasskeyVerificationIdentifier,
];

const domain = 'auth0.local';
const base = `https://${domain}`;
const clientId = '<client_id>';
const sessionSecret = '<secret>';
const realm = 'Username-Password-Authentication';
const WEBAUTHN_GRANT = 'urn:okta:params:oauth:grant-type:webauthn';
const FLOW_COOKIE = '__a0_passkey_tx';
const SESSION_COOKIE = '__a0_session.0';

// ─── A fake Auth0 that records what the SDK sends ──────────────────────────────────────────────

interface Call {
  body: Record<string, unknown>;
  headers: Headers;
}

const calls = { register: [] as Call[], challenge: [] as Call[], token: [] as Call[] };
let verificationRequired: Array<'email' | 'phone'> | undefined;
let tokenReplies: Array<() => Response | Promise<Response>> = [];

const record = async (list: Call[], request: Request) => {
  list.push({ body: (await request.json()) as Record<string, unknown>, headers: request.headers });
};

/** The token endpoint's answer to a wrong code: the identifiers that still need a code. */
const wrongCode = (remaining: Array<'email' | 'phone'>) => () =>
  HttpResponse.json(
    {
      error: 'invalid_grant',
      error_description: 'Invalid or expired session',
      auth_session: 'auth-session-signup',
      verification_required: remaining,
    },
    { status: 400 }
  );

const server = setupServer(
  http.get(`${base}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: `${base}/`,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/oauth/token`,
      end_session_endpoint: `${base}/logout`,
    })
  ),
  http.post(`${base}/passkey/register`, async ({ request }) => {
    await record(calls.register, request);
    return HttpResponse.json({
      auth_session: 'auth-session-signup',
      authn_params_public_key: {
        challenge: 'c2lnbnVwLWNoYWxsZW5nZQ',
        rp: { id: domain, name: domain },
        user: { id: 'dXNlci1oYW5kbGU', name: 'user@example.com', displayName: 'User' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: verificationRequired ? 900000 : 60000,
      },
      ...(verificationRequired && { verification_required: verificationRequired }),
    });
  }),
  http.post(`${base}/passkey/challenge`, async ({ request }) => {
    await record(calls.challenge, request);
    return HttpResponse.json({
      auth_session: 'auth-session-login',
      authn_params_public_key: { challenge: 'bG9naW4tY2hhbGxlbmdl', rpId: domain, timeout: 60000 },
    });
  }),
  http.post(`${base}/oauth/token`, async ({ request }) => {
    await record(calls.token, request);
    const reply = tokenReplies.shift();
    if (reply) {
      return reply();
    }
    return HttpResponse.json({
      access_token: 'access-token',
      id_token: await generateToken(domain, 'auth0|passkey-user', clientId),
      expires_in: 60,
      token_type: 'Bearer',
    });
  })
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  verificationRequired = undefined;
  tokenReplies = [];
  calls.register.length = 0;
  calls.challenge.length = 0;
  calls.token.length = 0;
});

// ─── The credentials a browser would send ──────────────────────────────────────────────────────

const clientData = (type: 'webauthn.create' | 'webauthn.get', challenge: string) =>
  Buffer.from(JSON.stringify({ type, challenge, origin: 'http://localhost:3000' })).toString('base64url');

const signupCredential: PasskeyCredentialResponse = {
  id: 'cred-id',
  rawId: 'cred-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: clientData('webauthn.create', 'c2lnbnVwLWNoYWxsZW5nZQ'),
    attestationObject: 'YXR0ZXN0YXRpb24',
  },
};

const loginCredential: PasskeyCredentialResponse = {
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

// ─── The routes under test: the calls of the "Login and Signup using Passkeys" section of EXAMPLES.md ───

type PluginOptions = Parameters<typeof fastifyAuth0>[1];

const forwardIp = (request: FastifyRequest) =>
  request.ip ? { headers: { 'auth0-forwarded-for': request.ip } } : undefined;

function buildApp(overrides: Partial<PluginOptions> = {}): FastifyInstance {
  // Tests only: `true` lets a test choose the user IP address with X-Forwarded-For. An app lists its proxies instead.
  const fastify = Fastify({ trustProxy: true });

  fastify.register(fastifyAuth0, {
    domain,
    clientId,
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret,
    ...overrides,
  } as PluginOptions);

  // 1a. Start a signup. When the connection verifies the email address or phone number, Auth0 sends the codes now.
  fastify.post<{ Body: PasskeyRegisterOptions }>('/api/passkey/signup/start', async (request, reply) => {
    // `request.body` is the browser's choice: validate it first (see "Securing the routes"), or it can set options such
    // as `organization` and `userMetadata`. The connection (`realm`) comes from the server.
    const { authnParamsPublicKey, verificationRequired } = await fastify.auth0Client!.passkey.startSignup(
      { ...request.body, realm },
      { request, reply },
      forwardIp(request)
    );

    return { authnParamsPublicKey, verificationRequired: verificationRequired ?? [] };
  });

  // 1b. Start a login.
  fastify.post('/api/passkey/login/start', async (request, reply) => {
    const { authnParamsPublicKey } = await fastify.auth0Client!.passkey.startLogin(
      { realm },
      { request, reply },
      forwardIp(request)
    );

    return { authnParamsPublicKey };
  });

  // 2. Complete a signup or a login. The SDK reads the flow from its cookie, exchanges the passkey for tokens and
  //    writes the session.
  fastify.post<{ Body: { credential: PasskeyCredentialResponse; verification?: PasskeyVerificationCodes } }>(
    '/api/passkey/complete',
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
        if (error instanceof PasskeyGetTokenError && error.isRetryable) {
          // A wrong code: ask again for the identifiers still listed, and send the same passkey.
          return reply.code(400).send({ status: 'retry', verificationRequired: error.verificationRequired ?? [] });
        }
        if (error instanceof PasskeyGetTokenError && error.statusCode === 429) {
          // Send the same request again later. Auth0 can say in `retry-after` how many seconds to wait.
          const retryAfter = Number(error.headers?.get('retry-after'));
          return reply.code(429).send({ status: 'wait', ...(retryAfter > 0 && { retryAfterSeconds: retryAfter }) });
        }
        if (isMfaRequiredError(error)) {
          // The passkey was accepted, but the user must also complete MFA. This route stops here and keeps no token: to
          // continue, keep `error.cause.mfa_token` on the server and use `fastify.auth0Client!.mfa`.
          return { status: 'mfa_required' };
        }
        if (error instanceof SessionExpiredError) {
          // The passkey was accepted, but the ID token says the session has already expired: no session, and the flow
          // is gone. Ask the user to sign in again.
          return reply.code(400).send({ status: 'session_expired' });
        }
        if (error instanceof MissingTransactionError) {
          return reply.code(400).send({ status: 'restart' }); // no flow, or it expired: start again
        }
        if (
          error instanceof MissingRequiredArgumentError ||
          (error instanceof PasskeyGetTokenError && error.cause?.error === 'invalid_request')
        ) {
          return reply.code(400).send({ status: 'invalid' }); // for example a missing code: fix the input, send again
        }

        // Log a summary, never the whole error: the `cause` of an Auth0 error can hold an `mfa_token`, and the error of
        // a session store can hold the session. A server or network failure has no `cause.error`, only `cause.message`.
        request.log.warn(
          error instanceof PasskeyGetTokenError
            ? { errorCode: error.cause?.error || error.cause?.message }
            : { errorMessage: error instanceof Error ? error.message : String(error) },
          'passkey.complete() failed'
        );
        return reply.code(400).send({ status: 'failed' });
      }
    }
  );

  fastify.get('/me', async (request, reply) => ({
    user: (await fastify.auth0Client!.getUser({ request, reply })) ?? null,
  }));

  fastify.get('/token', async (request, reply) => ({
    accessToken: (await fastify.auth0Client!.getAccessToken({ request, reply })).accessToken,
  }));

  return fastify;
}

// ─── Helpers: a cookie jar that behaves like a browser, and a fake store for direct SDK calls ───

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

const flowCookie = (res: Res) => setCookies(res).find((cookie) => cookie.startsWith(`${FLOW_COOKIE}=`));
const sessionCookie = (res: Res) => setCookies(res).find((cookie) => cookie.startsWith(`${SESSION_COOKIE}=`));
const cookieValue = (cookie: string) => cookie.split(';')[0]!.split('=').slice(1).join('=');

/** The attributes of a Set-Cookie header, keyed in lower case: `Max-Age=60` becomes `{ 'max-age': '60' }`. */
const attributes = (cookie: string) =>
  Object.fromEntries(
    cookie
      .split('; ')
      .slice(1)
      .map((part) => {
        const [key = '', ...value] = part.split('=');
        return [key.toLowerCase(), value.length > 0 ? value.join('=') : true];
      })
  );

const sessionState = async (res: Res) =>
  (await decrypt(cookieValue(sessionCookie(res)!), sessionSecret, '__a0_session')) as unknown as StateData;

const post = (
  app: FastifyInstance,
  url: string,
  payload: unknown,
  cookie?: string,
  headers: Record<string, string> = {}
) =>
  app.inject({
    method: 'POST',
    url,
    payload: JSON.stringify(payload),
    headers: { 'content-type': 'application/json', ...(cookie && { cookie }), ...headers },
  });

/** Stands in for `{ request, reply }` when a test calls the SDK directly. */
function fakeStore(cookies: Record<string, string> = {}) {
  const reply = { setCookie: vi.fn(), clearCookie: vi.fn() };
  const store = { request: { cookies }, reply } as unknown as StoreOptions;
  return { reply, store };
}

const cookiesFrom = (reply: { setCookie: ReturnType<typeof vi.fn> }): Record<string, string> =>
  Object.fromEntries((reply.setCookie.mock.calls as Array<[string, string]>).map(([name, value]) => [name, value]));

async function authClient() {
  const app = buildApp();
  await app.ready();
  return app.auth0Client!;
}

// ─── Starting a flow ───────────────────────────────────────────────────────────────────────────

test('signup start keeps the flow in an HttpOnly cookie, and the body never holds the authSession', async () => {
  const res = await post(buildApp(), '/api/passkey/signup/start', { email: 'user@example.com' });

  expect(res.statusCode).toBe(200);
  expect(res.json()).toMatchObject({
    authnParamsPublicKey: { challenge: 'c2lnbnVwLWNoYWxsZW5nZQ' },
    verificationRequired: [],
  });
  expect(res.body).not.toMatch(/auth.?session/i);

  const cookie = flowCookie(res)!;
  expect(attributes(cookie)).toMatchObject({ 'max-age': '60', path: '/', httponly: true, samesite: 'Lax' });
  expect(cookie).not.toContain('auth-session-signup'); // the value is encrypted
});

test('signup start sends the profile, the connection and the user IP to Auth0', async () => {
  await post(
    buildApp(),
    '/api/passkey/signup/start',
    { email: 'user@example.com', phoneNumber: '+14155550100', name: 'Jane', deliveryMethod: 'voice' },
    undefined,
    { 'x-forwarded-for': '203.0.113.9' }
  );

  const [register] = calls.register;
  expect(register?.body).toMatchObject({
    client_id: clientId,
    client_secret: '<client_secret>',
    realm,
    delivery_method: 'voice',
    user_profile: { email: 'user@example.com', phone_number: '+14155550100', name: 'Jane' },
  });
  expect(register?.headers.get('auth0-forwarded-for')).toBe('203.0.113.9');
});

test('a signup with only a phone number asks for the phone code', async () => {
  verificationRequired = ['phone'];
  const res = await post(buildApp(), '/api/passkey/signup/start', { phoneNumber: '+14155550100' });

  expect(res.json().verificationRequired).toEqual(['phone']);
  expect(calls.register[0]?.body.user_profile).toMatchObject({ phone_number: '+14155550100' });
  expect(calls.register[0]?.body.user_profile).not.toHaveProperty('email');
});

test('signup start lists the identifiers to verify, and keeps the flow for 15 minutes', async () => {
  verificationRequired = ['email', 'phone'];
  const res = await post(buildApp(), '/api/passkey/signup/start', {
    email: 'user@example.com',
    phoneNumber: '+14155550100',
  });

  expect(res.json().verificationRequired).toEqual(['email', 'phone']);
  expect(attributes(flowCookie(res)!)).toMatchObject({ 'max-age': '900' });
});

test('login start asks Auth0 for a challenge on the connection', async () => {
  const res = await post(buildApp(), '/api/passkey/login/start', {});

  expect(res.json()).toMatchObject({ authnParamsPublicKey: { challenge: 'bG9naW4tY2hhbGxlbmdl', rpId: domain } });
  expect(calls.challenge[0]?.body).toMatchObject({ client_id: clientId, realm });
  expect(attributes(flowCookie(res)!)).toMatchObject({ 'max-age': '60', httponly: true });
});

// ─── Completing a flow ─────────────────────────────────────────────────────────────────────────

test('complete after a signup creates the session and clears the flow', async () => {
  const app = buildApp();
  const start = await post(app, '/api/passkey/signup/start', { email: 'user@example.com' });
  const done = await post(app, '/api/passkey/complete', { credential: signupCredential }, jar(start));

  expect(done.json()).toEqual({ status: 'complete' });
  expect(calls.token[0]?.body).toMatchObject({
    grant_type: WEBAUTHN_GRANT,
    auth_session: 'auth-session-signup',
    client_id: clientId,
    client_secret: '<client_secret>',
    authn_response: { id: 'cred-id', response: { attestationObject: 'YXR0ZXN0YXRpb24' } },
  });
  expect(calls.token[0]?.body).not.toHaveProperty('verification');
  expect(attributes(flowCookie(done)!)).toMatchObject({ 'max-age': '0' });

  expect((await sessionState(done)).user?.sub).toBe('auth0|passkey-user');

  const me = await app.inject({ method: 'GET', url: '/me', headers: { cookie: jar(start, done) } });
  expect(me.json().user.sub).toBe('auth0|passkey-user');
});

test('complete after a login creates the session and clears the flow', async () => {
  const app = buildApp();
  const start = await post(app, '/api/passkey/login/start', {});
  const done = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));

  expect(done.json()).toEqual({ status: 'complete' });
  expect(calls.token[0]?.body).toMatchObject({ grant_type: WEBAUTHN_GRANT, auth_session: 'auth-session-login' });
  expect(attributes(flowCookie(done)!)).toMatchObject({ 'max-age': '0' });
  expect(sessionCookie(done)).toBeDefined();
});

test('a wrong code keeps the flow with the shorter list, and sets no session', async () => {
  verificationRequired = ['email', 'phone'];
  const app = buildApp();
  const start = await post(app, '/api/passkey/signup/start', {
    email: 'user@example.com',
    phoneNumber: '+14155550100',
  });
  tokenReplies.push(wrongCode(['phone']));

  const wrong = await post(
    app,
    '/api/passkey/complete',
    { credential: signupCredential, verification: { email: '123456', phone: '000000' } },
    jar(start)
  );

  expect(wrong.statusCode).toBe(400);
  expect(wrong.json()).toEqual({ status: 'retry', verificationRequired: ['phone'] });
  expect(sessionCookie(wrong)).toBeUndefined();

  const stored = await decrypt(cookieValue(flowCookie(wrong)!), sessionSecret, FLOW_COOKIE);
  expect(stored).toMatchObject({ authSession: 'auth-session-signup', verificationRequired: ['phone'] });
});

test('the retry after a wrong code sends only the remaining code, and the same credential', async () => {
  verificationRequired = ['email', 'phone'];
  const app = buildApp();
  const start = await post(app, '/api/passkey/signup/start', {
    email: 'user@example.com',
    phoneNumber: '+14155550100',
  });
  tokenReplies.push(wrongCode(['phone']));
  const wrong = await post(
    app,
    '/api/passkey/complete',
    { credential: signupCredential, verification: { email: '123456', phone: '000000' } },
    jar(start)
  );

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
  expect(calls.token[1]?.body.auth_session).toBe('auth-session-signup');
  expect(sessionCookie(retry)).toBeDefined();
});

test.each([
  ['a code is missing', { email: '123456' }],
  ['a code is blank', { email: '123456', phone: '   ' }],
])('complete answers invalid, without calling Auth0 and keeping the flow, when %s', async (_label, verification) => {
  verificationRequired = ['email', 'phone'];
  const app = buildApp();
  const start = await post(app, '/api/passkey/signup/start', {
    email: 'user@example.com',
    phoneNumber: '+14155550100',
  });

  const res = await post(app, '/api/passkey/complete', { credential: signupCredential, verification }, jar(start));

  expect(res.statusCode).toBe(400);
  expect(res.json()).toEqual({ status: 'invalid' });
  expect(calls.token).toHaveLength(0);
  expect(flowCookie(res)).toBeUndefined(); // neither cleared nor rewritten

  const done = await post(
    app,
    '/api/passkey/complete',
    { credential: signupCredential, verification: { email: '123456', phone: '654321' } },
    jar(start, res)
  );
  expect(done.json()).toEqual({ status: 'complete' });
});

test('an empty verification object is not sent to Auth0', async () => {
  const app = buildApp();
  const start = await post(app, '/api/passkey/login/start', {});

  await post(app, '/api/passkey/complete', { credential: loginCredential, verification: {} }, jar(start));

  expect(calls.token[0]?.body).not.toHaveProperty('verification');
});

const nowInSeconds = () => Math.floor(Date.now() / 1000);

/** A flow cookie as the SDK writes it after the login start of the fake Auth0, sealed with the given secret. */
async function loginFlowCookie(
  secret: string,
  { flowExpiresAt = nowInSeconds() + 60, cookieExpiresAt = nowInSeconds() + 60 } = {}
) {
  const flow = {
    authSession: 'auth-session-login',
    challenge: 'bG9naW4tY2hhbGxlbmdl',
    domain,
    expiresAt: flowExpiresAt,
  };

  return `${FLOW_COOKIE}=${await encrypt(flow, secret, FLOW_COOKIE, cookieExpiresAt)}`;
}

test('a flow cookie made by hand completes, so the restart cases below differ only in what they change', async () => {
  const cookie = await loginFlowCookie(sessionSecret);
  const res = await post(buildApp(), '/api/passkey/complete', { credential: loginCredential }, cookie);

  expect(res.json()).toEqual({ status: 'complete' });
  expect(calls.token).toHaveLength(1);
});

const unusableFlows: Array<[string, () => Promise<string | undefined>]> = [
  ['there is no flow cookie', async () => undefined],
  ['the flow cookie cannot be read', async () => `${FLOW_COOKIE}=not-a-valid-cookie`],
  ['the flow cookie was written under another session secret', () => loginFlowCookie('a-previous-secret')],
  ['the flow has expired', () => loginFlowCookie(sessionSecret, { flowExpiresAt: nowInSeconds() - 5 })],
  ['the flow cookie has expired', () => loginFlowCookie(sessionSecret, { cookieExpiresAt: nowInSeconds() - 60 })],
];

test.each(unusableFlows)('complete answers restart, without calling Auth0, when %s', async (_label, makeCookie) => {
  const res = await post(buildApp(), '/api/passkey/complete', { credential: loginCredential }, await makeCookie());

  expect(res.statusCode).toBe(400);
  expect(res.json()).toEqual({ status: 'restart' });
  expect(calls.token).toHaveLength(0);
});

test('a newer start replaces the pending flow: finishing the older one answers restart, without calling Auth0', async () => {
  const app = buildApp();
  const signup = await post(app, '/api/passkey/signup/start', { email: 'user@example.com' });
  const login = await post(app, '/api/passkey/login/start', {}, jar(signup)); // for example in another tab

  // The browser now holds the login flow. The signup credential carries the signup challenge.
  const res = await post(app, '/api/passkey/complete', { credential: signupCredential }, jar(signup, login));

  expect(res.json()).toEqual({ status: 'restart' });
  expect(calls.token).toHaveLength(0);
});

test('a temporary Auth0 failure keeps the flow, so sending the same request again works', async () => {
  const app = buildApp();
  const start = await post(app, '/api/passkey/login/start', {});
  tokenReplies.push(() => HttpResponse.json({ error: 'server_error' }, { status: 500 }));

  const first = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));
  expect(first.json()).toEqual({ status: 'failed' });
  expect(flowCookie(first)).toBeUndefined(); // neither cleared nor rewritten

  const second = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start, first));
  expect(second.json()).toEqual({ status: 'complete' });
  expect(calls.token).toHaveLength(2);
});

test('a rate limited complete answers wait with the seconds from retry-after, when Auth0 sent them', async () => {
  const app = buildApp();
  const start = await post(app, '/api/passkey/login/start', {});
  const limited = { error: 'too_many_requests', error_description: 'Too Many Requests' };
  tokenReplies.push(
    () => HttpResponse.json(limited, { status: 429, headers: { 'retry-after': '7' } }),
    () => HttpResponse.json(limited, { status: 429 })
  );

  const withSeconds = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));
  expect([withSeconds.statusCode, withSeconds.json()]).toEqual([429, { status: 'wait', retryAfterSeconds: 7 }]);

  const withoutSeconds = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));
  expect([withoutSeconds.statusCode, withoutSeconds.json()]).toEqual([429, { status: 'wait' }]);
});

// `complete()` deletes the flow before it creates the session, so the flow is gone if that step fails.

test('a session_expiry that has passed creates no session and ends the flow: session_expired, then restart', async () => {
  const app = buildApp();
  const start = await post(app, '/api/passkey/login/start', {});
  tokenReplies.push(async () =>
    HttpResponse.json({
      access_token: 'access-token',
      id_token: await generateToken(domain, 'auth0|passkey-user', clientId, undefined, undefined, undefined, {
        session_expiry: Math.floor(Date.now() / 1000) - 60,
      }),
      expires_in: 60,
      token_type: 'Bearer',
    })
  );

  const first = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));
  expect([first.statusCode, first.json()]).toEqual([400, { status: 'session_expired' }]);
  expect(sessionCookie(first)).toBeUndefined();
  expect(attributes(flowCookie(first)!)).toMatchObject({ 'max-age': '0' });

  const second = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start, first));
  expect(second.json()).toEqual({ status: 'restart' });
  expect(calls.token).toHaveLength(1); // Auth0 was not called again
});

test('a session store that throws also ends the flow: failed, then restart', async () => {
  const app = buildApp({
    sessionStore: {
      get: async () => undefined,
      set: async () => {
        throw new Error('the store is down');
      },
      delete: async () => {},
      deleteByLogoutToken: async () => {},
    },
  });
  const start = await post(app, '/api/passkey/login/start', {});

  const first = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));
  expect([first.statusCode, first.json()]).toEqual([400, { status: 'failed' }]);
  expect(attributes(flowCookie(first)!)).toMatchObject({ 'max-age': '0' });

  const second = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start, first));
  expect(second.json()).toEqual({ status: 'restart' });
  expect(calls.token).toHaveLength(1);
});

// ─── Errors, seen from the SDK directly ───────────────────────────────────────────────────────

test('mfa_required: no session, the flow is cleared, and isMfaRequiredError tells it apart', async () => {
  const client = await authClient();
  const start = fakeStore();
  await client.passkey.startLogin({ realm }, start.store);
  tokenReplies.push(() =>
    HttpResponse.json(
      {
        error: 'mfa_required',
        error_description: 'Multifactor authentication required',
        mfa_token: 'mfa-token-secret',
      },
      { status: 403 }
    )
  );

  const finish = fakeStore(cookiesFrom(start.reply));
  const error = await client.passkey.complete({ credential: loginCredential }, finish.store).catch((e: unknown) => e);

  expect(isMfaRequiredError(error)).toBe(true);
  expect(finish.reply.setCookie).not.toHaveBeenCalled(); // no session
  expect(finish.reply.clearCookie).toHaveBeenCalledWith(FLOW_COOKIE);
});

test('a rate limited complete throws a PasskeyGetTokenError with the status, and keeps the flow', async () => {
  const client = await authClient();
  const start = fakeStore();
  await client.passkey.startLogin({ realm }, start.store);
  tokenReplies.push(() =>
    HttpResponse.json(
      { error: 'too_many_requests', error_description: 'Too Many Requests' },
      { status: 429, headers: { 'retry-after': '7' } }
    )
  );

  const finish = fakeStore(cookiesFrom(start.reply));
  const error = await client.passkey.complete({ credential: loginCredential }, finish.store).catch((e: unknown) => e);

  expect(error).toBeInstanceOf(PasskeyGetTokenError);
  expect((error as PasskeyGetTokenError).statusCode).toBe(429);
  expect((error as PasskeyGetTokenError).headers?.get('retry-after')).toBe('7');
  expect(finish.reply.clearCookie).not.toHaveBeenCalled();
  expect(finish.reply.setCookie).not.toHaveBeenCalled();
});

test('a signup that Auth0 rejects throws PasskeyRegisterError, and stores no flow', async () => {
  server.use(
    http.post(`${base}/passkey/register`, () =>
      HttpResponse.json({ error: 'invalid_request', error_description: 'Rejected' }, { status: 400 })
    )
  );
  const client = await authClient();
  const { reply, store } = fakeStore();

  const error = await client.passkey.startSignup({ email: 'user@example.com' }, store).catch((e: unknown) => e);

  expect(error).toBeInstanceOf(PasskeyRegisterError);
  expect((error as PasskeyRegisterError).statusCode).toBe(400);
  expect(reply.setCookie).not.toHaveBeenCalled();
});

// The EXAMPLES.md sentence about the start routes: with no error handler of its own, Fastify answers with the status
// and the description from Auth0.
test('the signup route answers an Auth0 refusal with its status and description, and stores no flow', async () => {
  server.use(
    http.post(`${base}/passkey/register`, () =>
      HttpResponse.json({ error: 'invalid_request', error_description: 'The user already exists.' }, { status: 400 })
    )
  );

  const res = await post(buildApp(), '/api/passkey/signup/start', { email: 'user@example.com' });

  expect(res.statusCode).toBe(400);
  expect(res.json()).toMatchObject({ code: 'passkey_register_error', message: 'The user already exists.' });
  expect(flowCookie(res)).toBeUndefined();
});

test('a login that Auth0 rejects throws PasskeyChallengeError, and stores no flow', async () => {
  server.use(
    http.post(`${base}/passkey/challenge`, () =>
      HttpResponse.json({ error: 'invalid_request', error_description: 'Rejected' }, { status: 400 })
    )
  );
  const client = await authClient();
  const { reply, store } = fakeStore();

  const error = await client.passkey.startLogin({ realm }, store).catch((e: unknown) => e);

  expect(error).toBeInstanceOf(PasskeyChallengeError);
  expect((error as PasskeyChallengeError).statusCode).toBe(400);
  expect(reply.setCookie).not.toHaveBeenCalled();
});

test('a passkey call without { request, reply } throws MissingStoreOptionsError', async () => {
  const client = await authClient();

  await expect(client.passkey.startLogin({ realm })).rejects.toBeInstanceOf(MissingStoreOptionsError);
  await expect(client.passkey.complete({ credential: loginCredential })).rejects.toBeInstanceOf(
    MissingStoreOptionsError
  );
});

// The warning in EXAMPLES.md: as of @auth0/auth0-server-js 1.17.0 the store options are checked after Auth0 is
// called, so startSignup() may already have sent the codes. If server-js changes this, update that warning.
test('startSignup() without { request, reply } throws MissingStoreOptionsError, but only after it called Auth0', async () => {
  const client = await authClient();

  await expect(client.passkey.startSignup({ email: 'user@example.com', realm })).rejects.toBeInstanceOf(
    MissingStoreOptionsError
  );
  expect(calls.register).toHaveLength(1);
});

// ─── Plugin options ───────────────────────────────────────────────────────────────────────────

test('the plugin audience is requested, stored with the token set, and used by getAccessToken()', async () => {
  const app = buildApp({ audience: 'https://api.example.com' });
  const start = await post(app, '/api/passkey/login/start', {});
  const done = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));

  expect(calls.token[0]?.body).toMatchObject({ audience: 'https://api.example.com' });
  expect((await sessionState(done)).tokenSets[0]).toMatchObject({ audience: 'https://api.example.com' });

  const token = await app.inject({ method: 'GET', url: '/token', headers: { cookie: jar(start, done) } });
  expect(token.json()).toEqual({ accessToken: 'access-token' });
});

test('a domain resolver is called with { request, reply }, and the flow uses the domain it returns', async () => {
  const resolver = vi.fn(async () => domain);
  const app = buildApp({ domain: resolver } as Partial<PluginOptions>);
  const start = await post(app, '/api/passkey/signup/start', { email: 'user@example.com' });
  const done = await post(app, '/api/passkey/complete', { credential: signupCredential }, jar(start));

  expect(done.json()).toEqual({ status: 'complete' });
  expect(resolver).toHaveBeenCalledWith(
    expect.objectContaining({ request: expect.anything(), reply: expect.anything() })
  );
  expect(calls.register).toHaveLength(1);
  expect(calls.token).toHaveLength(1);
});

test('a stateful sessionStore receives the session', async () => {
  const sessions = new Map<string, StateData>();
  const app = buildApp({
    sessionStore: {
      get: async (id: string) => sessions.get(id),
      set: async (id: string, data: StateData) => {
        sessions.set(id, data);
      },
      delete: async (id: string) => {
        sessions.delete(id);
      },
      deleteByLogoutToken: async () => {},
    },
  });
  const start = await post(app, '/api/passkey/login/start', {});
  const done = await post(app, '/api/passkey/complete', { credential: loginCredential }, jar(start));

  expect(done.json()).toEqual({ status: 'complete' });
  expect(sessions.size).toBe(1);
  expect([...sessions.values()][0]?.user?.sub).toBe('auth0|passkey-user');
});

// ─── The package root ─────────────────────────────────────────────────────────────────────────

test('the package root exports the passkey errors and helpers', () => {
  for (const name of [
    'PasskeyRegisterError',
    'PasskeyChallengeError',
    'PasskeyGetTokenError',
    'MissingTransactionError',
    'SessionExpiredError',
    'isMfaRequiredError',
  ] as const) {
    expect(sdk[name], name).toBeTypeOf('function');
  }
});

// ─── The docs ─────────────────────────────────────────────────────────────────────────────────

test('the routes in EXAMPLES.md are the routes tested here', () => {
  // A checkout on Windows can have CRLF line endings.
  const read = (url: URL | string) => readFileSync(url, 'utf8').replace(/\r\n/g, '\n');
  const docs = read(new URL('../EXAMPLES.md', import.meta.url));
  const start = docs.indexOf('## Login and Signup using Passkeys');
  expect(start, 'the passkeys section in EXAMPLES.md').toBeGreaterThan(-1);
  const section = docs.slice(start);
  // Each anchor must be found: a check against an empty text would pass whatever the docs say.
  const first = section.indexOf('// 1a.');
  expect(first, 'the first route (// 1a.) in the passkeys section of EXAMPLES.md').toBeGreaterThan(-1);
  const routes = section.slice(first, section.indexOf('\n```', first));
  const inBuildApp = routes.replace(/^(?=.)/gm, '  '); // buildApp() holds the routes, indented by two spaces

  const spec = read(fileURLToPath(import.meta.url));
  expect(spec.includes(inBuildApp), 'The routes in EXAMPLES.md differ from the routes in passkey.spec.ts').toBe(true);

  const forwardIpInDocs = /^const forwardIp =[^;]*;$/m.exec(section)?.[0];
  expect(forwardIpInDocs, 'the forwardIp helper in the passkeys section of EXAMPLES.md').toBeDefined();
  expect(spec.includes(forwardIpInDocs as string), 'forwardIp in EXAMPLES.md differs from passkey.spec.ts').toBe(true);
});
