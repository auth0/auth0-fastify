import { expect, test, afterAll, afterEach, beforeAll, beforeEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken } from './test-utils/tokens.js';
import Fastify from 'fastify';
import plugin from './index.js';
import { StateData, TokenExchangeErrorCode } from '@auth0/auth0-server-js';
import { decrypt, encrypt } from './test-utils/encryption.js';

const domain = 'auth0.local';
let accessToken: string;
let mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.post(mockOpenIdConfiguration.backchannel_authentication_endpoint, () => {
    return HttpResponse.json({
      auth_req_id: 'auth_req_123',
      expires_in: 60,
    });
  }),

  http.post(mockOpenIdConfiguration.token_endpoint, async () => {
    return HttpResponse.json({
      access_token: accessToken,
      id_token: await generateToken(domain, 'user_123', '<client_id>'),
      expires_in: 60,
      token_type: 'Bearer',
    });
  }),
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));

// Close server after all tests
afterAll(() => server.close());

beforeEach(async () => {
  accessToken = await generateToken(domain, 'user_123');
});

afterEach(() => {
  mockOpenIdConfiguration = {
    issuer: `https://${domain}/`,
    authorization_endpoint: `https://${domain}/authorize`,
    backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
    token_endpoint: `https://${domain}/custom/token`,
    end_session_endpoint: `https://${domain}/logout`,
  };
  server.resetHandlers();
});

test('auth/login redirects to authorize', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/auth/callback');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(6);
});

test('auth/login redirects to authorize when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000/subpath',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/subpath/auth/callback');
  expect(url.searchParams.get('scope')).toBe('openid profile email offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.size).toBe(6);
});

test('auth/login infers appBaseUrl from request when using a domain resolver', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: async () => domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login',
    headers: {
      host: 'app.example.com',
      'x-forwarded-proto': 'https',
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.searchParams.get('redirect_uri')).toBe('https://app.example.com/auth/callback');
});

test('auth/login prefers forwarded host/proto when inferring appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: async () => domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login',
    headers: {
      host: 'internal.example.local',
      'x-forwarded-host': 'public.example.com',
      'x-forwarded-proto': 'https',
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.searchParams.get('redirect_uri')).toBe('https://public.example.com/auth/callback');
});

test('auth/login fails when appBaseUrl cannot be inferred', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: async () => domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login',
    headers: {
      host: '',
      'x-forwarded-proto': '',
    },
  });

  expect(res.statusCode).toBe(500);
});

test('auth/logout infers appBaseUrl from request when using a domain resolver', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: async () => domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/logout',
    headers: {
      host: 'app.example.com',
      'x-forwarded-proto': 'https',
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  const returnTo =
    url.searchParams.get('returnTo') ?? url.searchParams.get('post_logout_redirect_uri');
  expect(returnTo).toBe('https://app.example.com');
});

test('requires appBaseUrl when using a static domain', async () => {
  const fastify = Fastify();
  // @ts-expect-error appBaseUrl required for static domain
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    sessionSecret: '<secret>',
  });

  await expect(fastify.ready()).rejects.toThrowError('appBaseUrl is required when domain is a string.');
});

test('auth/login should put the appState in the transaction store', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?returnTo=http://localhost:3000/custom-return',
  });
  const cookieName = '__a0_tx';
  const cookieValueRaw = fastify.parseCookie(res.headers['set-cookie']?.toString() as string)[cookieName] as string;
  const cookieValue = (await decrypt(cookieValueRaw, '<secret>', '__a0_tx')) as { appState: { returnTo: string } };

  expect(cookieValue?.appState?.returnTo).toBe('http://localhost:3000/custom-return');
});

test('auth/login uses custom route when provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    routes: {
      login: '/custom-auth/login',
      callback: '/custom-auth/callback',
    },
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/custom-auth/login',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/custom-auth/callback');
});

test('auth/callback redirects to /', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/');
  expect(url.searchParams.size).toBe(0);
});

test('auth/callback redirects to / when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000/subpath',
    sessionSecret: '<secret>',
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/subpath');
  expect(url.searchParams.size).toBe(0);
});

test('auth/callback redirects to returnTo in state', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt(
    { appState: { returnTo: 'http://localhost:3000/custom-return' } },
    '<secret>',
    cookieName,
    Date.now() + 1000
  );
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/custom-return');
  expect(url.searchParams.size).toBe(0);
});

test('auth/callback uses custom route when provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    routes: {
      callback: '/custom-auth/callback',
    },
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/custom-auth/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/');
  expect(url.searchParams.size).toBe(0);
});

test('auth/logout redirects to logout', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/logout',
  });
  const url = new URL(res.headers['location']?.toString() || '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/logout');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('post_logout_redirect_uri')).toBe('http://localhost:3000');
  expect(url.searchParams.size).toBe(2);
});

test('auth/logout uses custom route when provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    routes: {
      logout: '/custom-auth/logout',
    },
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/custom-auth/logout',
  });
  const url = new URL(res.headers['location']?.toString() || '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/logout');
});

test('auth/connect returns 400 when connection not provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/connect?connectionScope=<connection_scope>',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('connection is required');
});

test('auth/connect redirects to authorize', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/connect?connection=<connection>&connectionScope=<connection_scope>',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/auth/connect/callback');
  expect(url.searchParams.get('scope')).toBe('openid link_account offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.get('requested_connection_scope')).toBe('<connection_scope>');
  expect(url.searchParams.size).toBe(9);
});

test('auth/connect redirects to authorize when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000/subpath',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/connect?connection=<connection>&connectionScope=<connection_scope>',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/subpath/auth/connect/callback');
  expect(url.searchParams.get('scope')).toBe('openid link_account offline_access');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.get('requested_connection_scope')).toBe('<connection_scope>');
  expect(url.searchParams.size).toBe(9);
});

test('auth/connect should put the appState in the transaction store', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const stateCookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/connect?connection=<connection>&connectionScope=<connection_scope>&returnTo=http://localhost:3000/custom-return',
    headers: {
      cookie: `__a0_session.0=${stateCookieValue}`,
    },
  });
  const cookieName = '__a0_tx';
  const cookieValueRaw = fastify.parseCookie(res.headers['set-cookie']?.toString() as string)[cookieName] as string;
  const cookieValue = (await decrypt(cookieValueRaw, '<secret>', cookieName)) as { appState: { returnTo: string } };

  expect(cookieValue?.appState?.returnTo).toBe('http://localhost:3000/custom-return');
});

test('auth/connect uses custom route when provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
    routes: {
      connect: '/custom-auth/connect',
    },
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/custom-auth/connect?connection=<connection>&connectionScope=<connection_scope>',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
});

test('auth/connect/callback redirects to /', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/connect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/');
  expect(url.searchParams.size).toBe(0);
});

test('auth/connect/callback redirects to / when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000/subpath',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/connect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/subpath');
  expect(url.searchParams.size).toBe(0);
});

test('auth/connect/callback redirects to returnTo in state', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt(
    { appState: { returnTo: 'http://localhost:3000/custom-return' } },
    '<secret>',
    cookieName,
    Date.now() + 1000
  );
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/connect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/custom-return');
  expect(url.searchParams.size).toBe(0);
});

test('auth/connect/callback uses custom route when provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
    routes: {
      connectCallback: '/custom-auth/connect/callback',
    },
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/custom-auth/connect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/');
  expect(url.searchParams.size).toBe(0);
});

test('auth/unconnect returns 400 when connection not provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/unconnect',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('connection is required');
});

test('auth/unconnect redirects to authorize', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/unconnect?connection=<connection>',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/auth/unconnect/callback');
  expect(url.searchParams.get('scope')).toBe('openid unlink_account');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.size).toBe(8);
});

test('auth/unconnect redirects to authorize when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000/subpath',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/unconnect?connection=<connection>',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/subpath/auth/unconnect/callback');
  expect(url.searchParams.get('scope')).toBe('openid unlink_account');
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('id_token_hint')).toBe('<id_token>');
  expect(url.searchParams.get('requested_connection')).toBe('<connection>');
  expect(url.searchParams.size).toBe(8);
});

test('auth/unconnect should put the appState in the transaction store', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const stateCookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/unconnect?connection=<connection>&returnTo=http://localhost:3000/custom-return',
    headers: {
      cookie: `__a0_session.0=${stateCookieValue}`,
    },
  });
  const cookieName = '__a0_tx';
  const cookieValueRaw = fastify.parseCookie(res.headers['set-cookie']?.toString() as string)[cookieName] as string;
  const cookieValue = (await decrypt(cookieValueRaw, '<secret>', cookieName)) as { appState: { returnTo: string } };

  expect(cookieValue?.appState?.returnTo).toBe('http://localhost:3000/custom-return');
});

test('auth/unconnect uses custom route when provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
    routes: {
      unconnect: '/custom-auth/unconnect',
      unconnectCallback: '/custom-auth/unconnect/callback',
    },
  });

  const stateData: StateData = {
    user: {
      sub: '<sub>',
    },
    idToken: '<id_token>',
    accessToken: '<access_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: '/custom-auth/unconnect?connection=<connection>',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  expect(url.searchParams.get('client_id')).toBe('<client_id>');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/custom-auth/unconnect/callback');
});

test('auth/unconnect/callback redirects to /', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/unconnect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/');
  expect(url.searchParams.size).toBe(0);
});

test('auth/unconnect/callback redirects to / when not using a root appBaseUrl', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000/subpath',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/unconnect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/subpath');
  expect(url.searchParams.size).toBe(0);
});

test('auth/unconnect/callback redirects to returnTo in state', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt(
    { appState: { returnTo: 'http://localhost:3000/custom-return' } },
    '<secret>',
    cookieName,
    Date.now() + 1000
  );
  const res = await fastify.inject({
    method: 'GET',
    url: `/auth/unconnect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });

  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/custom-return');
  expect(url.searchParams.size).toBe(0);
});

test('auth/unconnect/callback uses custom route when provided', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    mountConnectRoutes: true,
    routes: {
      unconnectCallback: '/custom-auth/unconnect/callback',
    },
  });

  const cookieName = '__a0_tx';
  const cookieValue = await encrypt({}, '<secret>', cookieName, Date.now() + 1000);
  const res = await fastify.inject({
    method: 'GET',
    url: `/custom-auth/unconnect/callback?code=123`,
    headers: {
      cookie: `${cookieName}=${cookieValue}`,
    },
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe('localhost:3000');
  expect(url.pathname).toBe('/');
  expect(url.searchParams.size).toBe(0);
});

test('loginWithCustomTokenExchange writes the exchanged user to the session', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/custom-token-exchange', async (request, reply) => {
    await fastify.auth0Client!.loginWithCustomTokenExchange(
      {
        subjectToken: 'external-token-123',
        subjectTokenType: 'urn:acme:legacy-token',
      },
      { request, reply }
    );

    return reply.send({ ok: true });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/custom-token-exchange',
  });

  expect(res.statusCode).toBe(200);

  const cookieName = '__a0_session';
  const cookieValueRaw = fastify.parseCookie(res.headers['set-cookie']?.toString() as string)[
    `${cookieName}.0`
  ] as string;
  const session = (await decrypt(cookieValueRaw, '<secret>', cookieName)) as StateData;

  expect(session.user?.sub).toBe('user_123');
});

test('loginWithCustomTokenExchange stores a token under the configured audience', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    audience: 'https://api.example.com',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/custom-token-exchange', async (request, reply) => {
    await fastify.auth0Client!.loginWithCustomTokenExchange(
      {
        subjectToken: 'external-token-123',
        subjectTokenType: 'urn:acme:legacy-token',
        audience: 'https://api.example.com',
      },
      { request, reply }
    );

    return reply.send({ ok: true });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/custom-token-exchange',
  });

  expect(res.statusCode).toBe(200);

  const cookieName = '__a0_session';
  const cookieValueRaw = fastify.parseCookie(res.headers['set-cookie']?.toString() as string)[
    `${cookieName}.0`
  ] as string;
  const session = (await decrypt(cookieValueRaw, '<secret>', cookieName)) as StateData;

  expect(session.tokenSets[0]?.audience).toBe('https://api.example.com');
  expect(session.tokenSets[0]?.accessToken).toBe(accessToken);
});

test('loginWithCustomTokenExchange persists the act claim on the session user', async () => {
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () => {
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', undefined, undefined, undefined, {
          act: { sub: 'service-account-id' },
        }),
        expires_in: 60,
        token_type: 'Bearer',
      });
    })
  );

  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/custom-token-exchange', async (request, reply) => {
    await fastify.auth0Client!.loginWithCustomTokenExchange(
      {
        subjectToken: 'user-token',
        subjectTokenType: 'urn:acme:user-token',
        actorToken: 'service-token',
        actorTokenType: 'urn:acme:service-token',
      },
      { request, reply }
    );

    return reply.send({ ok: true });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/custom-token-exchange',
  });

  expect(res.statusCode).toBe(200);

  const cookieName = '__a0_session';
  const cookieValueRaw = fastify.parseCookie(res.headers['set-cookie']?.toString() as string)[
    `${cookieName}.0`
  ] as string;
  const session = (await decrypt(cookieValueRaw, '<secret>', cookieName)) as StateData;

  expect((session.user?.act as { sub: string })?.sub).toBe('service-account-id');
});

test('customTokenExchange returns a token without creating a session', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/delegate', async (request, reply) => {
    const tokenResponse = await fastify.auth0Client!.customTokenExchange(
      {
        subjectToken: 'external-token-123',
        subjectTokenType: 'urn:acme:legacy-token',
      },
      { request, reply }
    );

    const session = await fastify.auth0Client!.getSession({ request, reply });
    return reply.send({ accessToken: tokenResponse.accessToken, hasSession: !!session });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/delegate',
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().accessToken).toBe(accessToken);
  expect(res.json().hasSession).toBe(false);
  expect(res.headers['set-cookie']).toBeUndefined();
});

test('customTokenExchange does not overwrite an existing session', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const stateData: StateData = {
    user: {
      sub: 'original-user',
    },
    idToken: '<id_token>',
    refreshToken: '<refresh_token>',
    tokenSets: [],
    internal: {
      sid: '<sid>',
      createdAt: 1234567890,
    },
  };
  const cookieValue = await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);

  fastify.post('/delegate', async (request, reply) => {
    await fastify.auth0Client!.customTokenExchange(
      {
        subjectToken: 'external-token-123',
        subjectTokenType: 'urn:acme:legacy-token',
      },
      { request, reply }
    );

    const session = await fastify.auth0Client!.getSession({ request, reply });
    return reply.send({ sub: session?.user?.sub });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/delegate',
    headers: {
      cookie: `__a0_session.0=${cookieValue}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().sub).toBe('original-user');
  expect(res.headers['set-cookie']).toBeUndefined();
});

test('customTokenExchange surfaces the act claim when an actor token is used', async () => {
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () => {
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', undefined, undefined, undefined, {
          act: { sub: 'service-account-id' },
        }),
        expires_in: 60,
        token_type: 'Bearer',
      });
    })
  );

  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/delegate', async (request, reply) => {
    const tokenResponse = await fastify.auth0Client!.customTokenExchange(
      {
        subjectToken: 'user-token',
        subjectTokenType: 'urn:acme:user-token',
        actorToken: 'service-token',
        actorTokenType: 'urn:acme:service-token',
      },
      { request, reply }
    );

    return reply.send({ act: tokenResponse.act });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/delegate',
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().act).toEqual({ sub: 'service-account-id' });
});

test('customTokenExchange throws when the exchange fails', async () => {
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, () => {
      return HttpResponse.json({ error: 'invalid_request', error_description: 'bad token' }, { status: 400 });
    })
  );

  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/delegate', async (request, reply) => {
    try {
      await fastify.auth0Client!.customTokenExchange(
        {
          subjectToken: 'external-token-123',
          subjectTokenType: 'urn:acme:legacy-token',
        },
        { request, reply }
      );
      return reply.send({ ok: true });
    } catch (e) {
      // auth0-server-js exposes TokenExchangeError as a type only, not a runtime
      // value, so we match on the error name rather than `instanceof`.
      return reply.code(400).send({ name: (e as Error).name });
    }
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/delegate',
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().name).toBe('TokenExchangeError');
});

test('customTokenExchange forwards the organization to the token endpoint', async () => {
  let capturedOrganization: string | null = null;
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
      const info = await request.formData();
      capturedOrganization = info.get('organization') as string;
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>', undefined, undefined, undefined, {
          org_id: 'org_123',
        }),
        expires_in: 60,
        token_type: 'Bearer',
      });
    })
  );

  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/delegate', async (request, reply) => {
    await fastify.auth0Client!.customTokenExchange({
      subjectToken: 'external-token-123',
      subjectTokenType: 'urn:acme:legacy-token',
      organization: 'org_123',
    });

    return reply.send({ ok: true });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/delegate',
  });

  expect(res.statusCode).toBe(200);
  expect(capturedOrganization).toBe('org_123');
});

// --- Impersonation via Session Transfer Token (STT) -------------------------------------------
//
// Two roles are covered here:
//   * Initiator — the support/admin app that mints an STT and redirects to the target.
//   * Target    — the customer's app whose `/auth/login` forwards the STT to `/authorize`.
//
// The STT is opaque, single-use and short-lived. The plugin only passes it through: these tests
// pin that it is never written to the session cookie on either side.

const SESSION_TRANSFER_TOKEN_TYPE = 'urn:auth0:params:oauth:token-type:session_transfer_token';
const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';

/**
 * Handler that emulates Auth0's STT mint. Recognises the exchange by the `:session_transfer`
 * audience, rejects a request with no `actor_token` the way the server does when the Action did
 * not call `setActor`, and captures the submitted form for assertions.
 */
const sessionTransferTokenHandler = (captured: Record<string, string | null> = {}) =>
  http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
    const info = await request.formData();
    const audience = info.get('audience');

    if (typeof audience === 'string' && audience.endsWith(':session_transfer')) {
      for (const key of ['audience', 'actor_token', 'actor_token_type', 'subject_token', 'subject_token_type', 'organization', 'scope', 'reason']) {
        captured[key] = info.get(key) as string | null;
      }

      if (!info.get('actor_token')) {
        return HttpResponse.json(
          {
            error: 'invalid_request',
            error_description: 'setActor is required when requesting a session transfer token via token exchange.',
          },
          { status: 400 }
        );
      }

      return HttpResponse.json({
        access_token: '<opaque-session-transfer-token>',
        issued_token_type: SESSION_TRANSFER_TOKEN_TYPE,
        token_type: 'N_A',
        expires_in: 60,
      });
    }

    // Any non-STT exchange on this endpoint (for example the actor-token refresh) keeps the
    // default behaviour so the refresh path can be exercised in the same test.
    return HttpResponse.json({
      access_token: accessToken,
      id_token: await generateToken(domain, 'agent_123', '<client_id>'),
      expires_in: 60,
      token_type: 'Bearer',
    });
  });

/** Builds an encrypted agent session cookie so the SDK can source the actor from it. */
const agentSessionCookie = async (idToken: string, refreshToken?: string) => {
  const stateData: StateData = {
    user: { sub: 'agent_123' },
    idToken,
    refreshToken,
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: Math.floor(Date.now() / 1000) },
  };

  return await encrypt(stateData, '<secret>', '__a0_session', Date.now() + 1000);
};

const registerInitiator = (fastify: ReturnType<typeof Fastify>) =>
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

test('requestSessionTransferToken mints an STT sourcing the actor from the agent session', async () => {
  const captured: Record<string, string | null> = {};
  server.use(sessionTransferTokenHandler(captured));

  const agentIdToken = await generateToken(domain, 'agent_123', '<client_id>');
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
      },
      { request, reply }
    );

    return reply.send(result);
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
    headers: { cookie: `__a0_session.0=${await agentSessionCookie(agentIdToken, '<refresh_token>')}` },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().sessionTransferToken).toBe('<opaque-session-transfer-token>');
  expect(res.json().issuedTokenType).toBe(SESSION_TRANSFER_TOKEN_TYPE);
  expect(res.json().expiresIn).toBeGreaterThan(0);

  // The audience is derived from the resolved domain, and the actor defaults to the session ID token.
  expect(captured.audience).toBe(`urn:${domain}:session_transfer`);
  expect(captured.actor_token).toBe(agentIdToken);
  expect(captured.actor_token_type).toBe(ID_TOKEN_TYPE);
  expect(captured.subject_token).toBe('customer-proof-token');
  expect(captured.subject_token_type).toBe('urn:acme:customer-subject');
});

test('requestSessionTransferToken forwards the organization on the mint request', async () => {
  const captured: Record<string, string | null> = {};
  server.use(sessionTransferTokenHandler(captured));

  const agentIdToken = await generateToken(domain, 'agent_123', '<client_id>');
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
        organization: 'org_globex',
      },
      { request, reply }
    );

    return reply.send(result);
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
    headers: { cookie: `__a0_session.0=${await agentSessionCookie(agentIdToken, '<refresh_token>')}` },
  });

  expect(res.statusCode).toBe(200);
  expect(captured.organization).toBe('org_globex');
});

test('requestSessionTransferToken omits the organization when it is not provided', async () => {
  const captured: Record<string, string | null> = {};
  server.use(sessionTransferTokenHandler(captured));

  const agentIdToken = await generateToken(domain, 'agent_123', '<client_id>');
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
      },
      { request, reply }
    );

    return reply.send(result);
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
    headers: { cookie: `__a0_session.0=${await agentSessionCookie(agentIdToken, '<refresh_token>')}` },
  });

  expect(res.statusCode).toBe(200);
  // Read off the form body, so this fails if an empty `organization=` is ever sent.
  expect(captured.organization).toBeNull();
});

test('requestSessionTransferToken rejects a blank organization before refreshing the agent session', async () => {
  // The session ID token is already expired, so resolving the actor would refresh it: a call to
  // the token endpoint plus a write of the rotated tokens back to the session cookie. A blank
  // organization has to be caught ahead of all that, not after.
  let tokenEndpointCalls = 0;
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () => {
      tokenEndpointCalls++;
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'agent_123', '<client_id>'),
        expires_in: 60,
        token_type: 'Bearer',
      });
    })
  );

  const expiredAgentIdToken = await generateToken(domain, 'agent_123', '<client_id>', undefined, undefined, 0);
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    try {
      await fastify.auth0Client!.requestSessionTransferToken(
        {
          subjectToken: 'customer-proof-token',
          subjectTokenType: 'urn:acme:customer-subject',
          organization: '   ',
        },
        { request, reply }
      );
    } catch (error) {
      return reply.code(400).send({ name: (error as Error).constructor.name });
    }

    return reply.send({ name: null });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
    headers: { cookie: `__a0_session.0=${await agentSessionCookie(expiredAgentIdToken, '<refresh_token>')}` },
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().name).toBe('OrganizationValidationError');
  // No refresh round trip and no rotated tokens persisted.
  expect(tokenEndpointCalls).toBe(0);
  expect(res.headers['set-cookie']).toBeUndefined();
});

test('requestSessionTransferToken never writes the STT to the session', async () => {
  server.use(sessionTransferTokenHandler());

  const agentIdToken = await generateToken(domain, 'agent_123', '<client_id>');
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
      },
      { request, reply }
    );

    // The agent's own session must be untouched by the exchange.
    const session = await fastify.auth0Client!.getSession({ request, reply });
    return reply.send({ stt: result.sessionTransferToken, agentSub: session?.user?.sub });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
    headers: { cookie: `__a0_session.0=${await agentSessionCookie(agentIdToken, '<refresh_token>')}` },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().agentSub).toBe('agent_123');

  // No cookie is set at all, so the STT cannot have leaked into the session.
  expect(res.headers['set-cookie']).toBeUndefined();
});

test('requestSessionTransferToken honours an explicit actor over the session', async () => {
  const captured: Record<string, string | null> = {};
  server.use(sessionTransferTokenHandler(captured));

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
        actor: { token: 'explicit-actor-token' },
      },
      { request, reply }
    );

    return reply.send({ issuedTokenType: result.issuedTokenType });
  });

  // No session cookie is sent: the explicit actor makes a logged-in agent unnecessary.
  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
  });

  expect(res.statusCode).toBe(200);
  expect(captured.actor_token).toBe('explicit-actor-token');
  // The actor type defaults to the ID token URN when omitted.
  expect(captured.actor_token_type).toBe(ID_TOKEN_TYPE);
});

test('requestSessionTransferToken forwards scope and extra parameters to the token endpoint', async () => {
  const captured: Record<string, string | null> = {};
  server.use(sessionTransferTokenHandler(captured));

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
        actor: { token: 'explicit-actor-token' },
        scope: 'openid profile',
        extra: { reason: 'Investigating TCK-4821' },
      },
      { request, reply }
    );

    return reply.send({ ok: true });
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(200);
  expect(captured.scope).toBe('openid profile');
  // `extra` reaches the Action through the token endpoint request body.
  expect(captured.reason).toBe('Investigating TCK-4821');
});

test('requestSessionTransferToken refreshes an expired agent ID token and uses the refreshed one as the actor', async () => {
  const captured: Record<string, string | null> = {};
  server.use(sessionTransferTokenHandler(captured));

  // An ID token that expired an hour ago cannot be used as an actor: the server rejects it.
  const expiredIdToken = await generateToken(
    domain,
    'agent_123',
    '<client_id>',
    undefined,
    undefined,
    Math.floor(Date.now() / 1000) - 3600
  );

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
      },
      { request, reply }
    );

    return reply.send({ issuedTokenType: result.issuedTokenType });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
    headers: { cookie: `__a0_session.0=${await agentSessionCookie(expiredIdToken, '<refresh_token>')}` },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().issuedTokenType).toBe(SESSION_TRANSFER_TOKEN_TYPE);

  // The stale token must not be sent as the actor; the refreshed one is used instead.
  expect(captured.actor_token).not.toBe(expiredIdToken);
  expect(captured.actor_token).toBeTruthy();

  // The refreshed agent session is persisted so rotation does not strand the refresh token.
  expect(res.headers['set-cookie']).toBeDefined();
});

test('requestSessionTransferToken throws actor_unavailable when there is no agent session', async () => {
  server.use(sessionTransferTokenHandler());

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    try {
      await fastify.auth0Client!.requestSessionTransferToken(
        {
          subjectToken: 'customer-proof-token',
          subjectTokenType: 'urn:acme:customer-subject',
        },
        { request, reply }
      );
      return reply.send({ ok: true });
    } catch (e) {
      const error = e as Error & { code?: string };
      return reply.code(400).send({ name: error.name, code: error.code });
    }
  });

  // No session cookie and no explicit actor: this fails client-side, before any network call.
  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(400);
  expect(res.json().name).toBe('TokenExchangeError');
  expect(res.json().code).toBe(TokenExchangeErrorCode.ACTOR_UNAVAILABLE);
});

test('requestSessionTransferToken throws actor_unavailable when the expired ID token cannot be refreshed', async () => {
  server.use(sessionTransferTokenHandler());

  const expiredIdToken = await generateToken(
    domain,
    'agent_123',
    '<client_id>',
    undefined,
    undefined,
    Math.floor(Date.now() / 1000) - 3600
  );

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    try {
      await fastify.auth0Client!.requestSessionTransferToken(
        {
          subjectToken: 'customer-proof-token',
          subjectTokenType: 'urn:acme:customer-subject',
        },
        { request, reply }
      );
      return reply.send({ ok: true });
    } catch (e) {
      const error = e as Error & { code?: string };
      return reply.code(400).send({ name: error.name, code: error.code });
    }
  });

  // The session carries an expired ID token and no refresh token, so the actor cannot be recovered.
  const res = await fastify.inject({
    method: 'POST',
    url: '/impersonate',
    headers: { cookie: `__a0_session.0=${await agentSessionCookie(expiredIdToken)}` },
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().code).toBe(TokenExchangeErrorCode.ACTOR_UNAVAILABLE);
});

test('requestSessionTransferToken surfaces a server-side setActor failure as a TokenExchangeError', async () => {
  // The mint handler rejects a request with no actor_token exactly as the server does when the
  // CTE Action did not call setActor. An explicit blank-free actor is bypassed here by sending
  // none at all, which is what the server sees when the Action omits setActor.
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, () =>
      HttpResponse.json(
        {
          error: 'invalid_request',
          error_description: 'setActor is required when requesting a session transfer token via token exchange.',
        },
        { status: 400 }
      )
    )
  );

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    try {
      await fastify.auth0Client!.requestSessionTransferToken(
        {
          subjectToken: 'customer-proof-token',
          subjectTokenType: 'urn:acme:customer-subject',
          actor: { token: 'explicit-actor-token' },
        },
        { request, reply }
      );
      return reply.send({ ok: true });
    } catch (e) {
      const error = e as Error & { cause?: { error?: string; error_description?: string } };
      return reply.code(400).send({ name: error.name, cause: error.cause?.error_description });
    }
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(400);
  expect(res.json().name).toBe('TokenExchangeError');
  expect(res.json().cause).toContain('setActor is required');
});

test('requestSessionTransferToken surfaces a disabled tenant feature flag as a TokenExchangeError', async () => {
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, () =>
      HttpResponse.json(
        { error: 'session_transfer_disabled', error_description: 'Session transfer is not enabled for this tenant.' },
        { status: 400 }
      )
    )
  );

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    try {
      await fastify.auth0Client!.requestSessionTransferToken(
        {
          subjectToken: 'customer-proof-token',
          subjectTokenType: 'urn:acme:customer-subject',
          actor: { token: 'explicit-actor-token' },
        },
        { request, reply }
      );
      return reply.send({ ok: true });
    } catch (e) {
      const error = e as Error & { cause?: { error?: string } };
      return reply.code(400).send({ name: error.name, cause: error.cause?.error });
    }
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(400);
  expect(res.json().name).toBe('TokenExchangeError');
  expect(res.json().cause).toBe(TokenExchangeErrorCode.SESSION_TRANSFER_DISABLED);
});

test('requestSessionTransferToken resolves the audience from the resolver domain (MCD)', async () => {
  const captured: Record<string, string | null> = {};
  server.use(sessionTransferTokenHandler(captured));

  const agentIdToken = await generateToken(domain, 'agent_123', '<client_id>');
  const fastify = Fastify();
  fastify.register(plugin, {
    // Resolver mode: only the default test domain has discovery handlers registered, so the
    // resolver returns it. The point of the test is that the audience follows the resolved
    // domain rather than a hard-coded value.
    domain: async () => domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
        actor: { token: agentIdToken },
      },
      { request, reply }
    );

    return reply.send({ issuedTokenType: result.issuedTokenType });
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(200);
  expect(captured.audience).toBe(`urn:${domain}:session_transfer`);
});

test('buildSessionTransferRedirect appends the STT to the target login URL', async () => {
  server.use(sessionTransferTokenHandler());

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
        actor: { token: 'explicit-actor-token' },
      },
      { request, reply }
    );

    const url = fastify.auth0Client!.buildSessionTransferRedirect('https://app.example.com/auth/login', result);

    return reply.redirect(url.href);
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(302);
  const url = new URL(res.headers['location']?.toString() ?? '');
  expect(url.origin).toBe('https://app.example.com');
  expect(url.pathname).toBe('/auth/login');
  expect(url.searchParams.get('session_transfer_token')).toBe('<opaque-session-transfer-token>');
  expect(url.searchParams.get('organization')).toBeNull();

  // Building the redirect writes nothing to the session.
  expect(res.headers['set-cookie']).toBeUndefined();
});

test('buildSessionTransferRedirect forwards the organization when provided', async () => {
  server.use(sessionTransferTokenHandler());

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
        actor: { token: 'explicit-actor-token' },
      },
      { request, reply }
    );

    const url = fastify.auth0Client!.buildSessionTransferRedirect('https://app.example.com/auth/login', result, {
      organization: 'org_globex',
    });

    return reply.send({ url: url.href });
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(200);
  const url = new URL(res.json().url);
  expect(url.searchParams.get('session_transfer_token')).toBe('<opaque-session-transfer-token>');
  expect(url.searchParams.get('organization')).toBe('org_globex');
});

test('buildSessionTransferRedirect preserves existing query parameters on the target URL', async () => {
  server.use(sessionTransferTokenHandler());

  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const result = await fastify.auth0Client!.requestSessionTransferToken(
      {
        subjectToken: 'customer-proof-token',
        subjectTokenType: 'urn:acme:customer-subject',
        actor: { token: 'explicit-actor-token' },
      },
      { request, reply }
    );

    const url = fastify.auth0Client!.buildSessionTransferRedirect(
      'https://app.example.com/auth/login?returnTo=%2Fdashboard',
      result
    );

    return reply.send({ url: url.href });
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(200);
  const url = new URL(res.json().url);
  expect(url.searchParams.get('returnTo')).toBe('/dashboard');
  expect(url.searchParams.get('session_transfer_token')).toBe('<opaque-session-transfer-token>');
});

test('buildSessionTransferRedirect rejects an insecure target login URL', async () => {
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    try {
      fastify.auth0Client!.buildSessionTransferRedirect('http://app.example.com/auth/login', {
        sessionTransferToken: '<opaque-session-transfer-token>',
        issuedTokenType: SESSION_TRANSFER_TOKEN_TYPE,
        expiresIn: 60,
      });
      return reply.send({ ok: true });
    } catch (e) {
      return reply.code(400).send({ name: (e as Error).name });
    }
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(400);
  expect(res.json().name).toBe('InvalidConfigurationError');
});

test('buildSessionTransferRedirect allows an http loopback target login URL for local development', async () => {
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    const url = fastify.auth0Client!.buildSessionTransferRedirect('http://localhost:3001/auth/login', {
      sessionTransferToken: '<opaque-session-transfer-token>',
      issuedTokenType: SESSION_TRANSFER_TOKEN_TYPE,
      expiresIn: 60,
    });

    return reply.send({ url: url.href });
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(200);
  const url = new URL(res.json().url);
  expect(url.origin).toBe('http://localhost:3001');
  expect(url.searchParams.get('session_transfer_token')).toBe('<opaque-session-transfer-token>');
});

test('buildSessionTransferRedirect rejects a relative target login URL', async () => {
  const fastify = Fastify();
  registerInitiator(fastify);

  fastify.post('/impersonate', async (request, reply) => {
    try {
      fastify.auth0Client!.buildSessionTransferRedirect('/auth/login', {
        sessionTransferToken: '<opaque-session-transfer-token>',
        issuedTokenType: SESSION_TRANSFER_TOKEN_TYPE,
        expiresIn: 60,
      });
      return reply.send({ ok: true });
    } catch (e) {
      return reply.code(400).send({ name: (e as Error).name });
    }
  });

  const res = await fastify.inject({ method: 'POST', url: '/impersonate' });

  expect(res.statusCode).toBe(400);
  expect(res.json().name).toBe('InvalidConfigurationError');
});

test('auth/login forwards session_transfer_token to authorize (target app)', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?session_transfer_token=stt_opaque_abc',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.host).toBe(domain);
  expect(url.pathname).toBe('/authorize');
  // The STT reaches /authorize so Auth0 can redeem it and establish the impersonation session.
  expect(url.searchParams.get('session_transfer_token')).toBe('stt_opaque_abc');
  // Redemption is still a standard authorization-code login.
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:3000/auth/callback');
  expect(url.searchParams.get('code_challenge')).toBeTypeOf('string');
});

test('auth/login forwards the organization alongside session_transfer_token (target app)', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?session_transfer_token=stt_opaque_abc&organization=org_globex',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.searchParams.get('session_transfer_token')).toBe('stt_opaque_abc');
  expect(url.searchParams.get('organization')).toBe('org_globex');
});

test('auth/login ignores the organization when no session_transfer_token is present', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?organization=org_globex',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  // `organization` is only honoured as part of an STT redirect, so a plain login is unchanged.
  expect(res.statusCode).toBe(302);
  expect(url.searchParams.get('organization')).toBeNull();
  expect(url.searchParams.get('session_transfer_token')).toBeNull();
});

test('auth/login ignores a blank organization alongside a session_transfer_token', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?session_transfer_token=stt_opaque_abc&organization=%20%20',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  // The STT still goes through, but a blank `organization` must be dropped rather than sent
  // as an empty `organization=`, which Auth0 would reject.
  expect(res.statusCode).toBe(302);
  expect(url.searchParams.get('session_transfer_token')).toBe('stt_opaque_abc');
  expect(url.searchParams.has('organization')).toBe(false);
});

test('auth/login ignores a blank session_transfer_token', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?session_transfer_token=%20%20',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  // A blank value must not be forwarded as an empty `session_transfer_token=` parameter.
  expect(res.statusCode).toBe(302);
  expect(url.searchParams.get('session_transfer_token')).toBeNull();
  expect(url.searchParams.get('response_type')).toBe('code');
});

test('auth/login takes the first value when session_transfer_token is repeated', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  // Fastify parses a repeated key into an array; the route must not crash on it.
  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?session_transfer_token=first&session_transfer_token=second',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.searchParams.get('session_transfer_token')).toBe('first');
});

test('auth/login still honours returnTo when redeeming an STT (target app)', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?session_transfer_token=stt_opaque_abc&returnTo=/dashboard',
  });

  expect(res.statusCode).toBe(302);
  const url = new URL(res.headers['location']?.toString() ?? '');
  expect(url.searchParams.get('session_transfer_token')).toBe('stt_opaque_abc');

  // returnTo is carried in the transaction cookie, not on the authorize URL.
  const cookieName = '__a0_tx';
  const cookieValueRaw = fastify.parseCookie(res.headers['set-cookie']?.toString() as string)[cookieName] as string;
  const transaction = (await decrypt(cookieValueRaw, '<secret>', cookieName)) as {
    appState?: { returnTo?: string };
  };
  expect(transaction.appState?.returnTo).toBe('http://localhost:3000/dashboard');
});

test('auth/login does not persist the session_transfer_token in the transaction cookie', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/auth/login?session_transfer_token=stt_opaque_abc',
  });

  expect(res.statusCode).toBe(302);

  // The STT is single-use and must only be passed through to /authorize, never stored.
  const cookieHeader = res.headers['set-cookie']?.toString() ?? '';
  expect(cookieHeader).not.toContain('stt_opaque_abc');

  const cookieName = '__a0_tx';
  const cookieValueRaw = fastify.parseCookie(cookieHeader)[cookieName] as string;
  const transaction = await decrypt(cookieValueRaw, '<secret>', cookieName);
  expect(JSON.stringify(transaction)).not.toContain('stt_opaque_abc');
});

test('auth/login forwards session_transfer_token on a custom login route', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
    routes: {
      login: '/custom-login',
    },
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/custom-login?session_transfer_token=stt_opaque_abc',
  });
  const url = new URL(res.headers['location']?.toString() ?? '');

  expect(res.statusCode).toBe(302);
  expect(url.searchParams.get('session_transfer_token')).toBe('stt_opaque_abc');
});
