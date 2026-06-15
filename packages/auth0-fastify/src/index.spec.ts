import { expect, test, afterAll, afterEach, beforeAll, beforeEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken } from './test-utils/tokens.js';
import Fastify from 'fastify';
import plugin from './index.js';
import { StateData } from '@auth0/auth0-server-js';
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
  fastify.register(plugin, {
    // @ts-expect-error appBaseUrl required for static domain
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

test('loginWithCustomTokenExchange persists session and returns user as authenticated', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/test/login-cte', async (request, reply) => {
    await fastify.auth0Client!.loginWithCustomTokenExchange(
      {
        subjectToken: 'external-token',
        subjectTokenType: 'urn:acme:legacy-token',
      },
      { request, reply }
    );
    return reply.send({ ok: true });
  });

  fastify.get('/test/session', async (request, reply) => {
    const session = await fastify.auth0Client!.getSession({ request, reply });
    return reply.send({ isAuthenticated: !!session?.user });
  });

  await fastify.ready();

  // Step 1: perform CTE — session cookie is set on the response
  const loginRes = await fastify.inject({ method: 'POST', url: '/test/login-cte' });
  expect(loginRes.statusCode).toBe(200);

  // Step 2: use the session cookie on a subsequent request
  const sessionCookie = loginRes.headers['set-cookie']?.toString() ?? '';
  const sessionRes = await fastify.inject({
    method: 'GET',
    url: '/test/session',
    headers: { cookie: sessionCookie },
  });

  expect(sessionRes.statusCode).toBe(200);
  expect(sessionRes.json().isAuthenticated).toBe(true);
});

test('loginWithCustomTokenExchange stores tokens in session so getAccessToken works', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/test/login-cte-token', async (request, reply) => {
    await fastify.auth0Client!.loginWithCustomTokenExchange(
      {
        subjectToken: 'external-token',
        subjectTokenType: 'urn:acme:legacy-token',
      },
      { request, reply }
    );
    return reply.send({ ok: true });
  });

  fastify.get('/test/access-token', async (request, reply) => {
    const tokenSet = await fastify.auth0Client!.getAccessToken({ request, reply });
    return reply.send({ accessToken: tokenSet.accessToken });
  });

  await fastify.ready();

  // Step 1: perform CTE — session cookie is set on the response
  const loginRes = await fastify.inject({ method: 'POST', url: '/test/login-cte-token' });
  expect(loginRes.statusCode).toBe(200);

  // Step 2: use the session cookie to retrieve the access token
  const sessionCookie = loginRes.headers['set-cookie']?.toString() ?? '';
  const tokenRes = await fastify.inject({
    method: 'GET',
    url: '/test/access-token',
    headers: { cookie: sessionCookie },
  });

  expect(tokenRes.statusCode).toBe(200);
  expect(tokenRes.json().accessToken).toBe(accessToken);
});

test('loginWithCustomTokenExchange passes actor token when provided', async () => {
  let capturedBody: Record<string, string> = {};
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
      capturedBody = Object.fromEntries(new URLSearchParams(await request.text()));
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(domain, 'user_123', '<client_id>'),
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

  fastify.post('/test/login-cte-actor', async (request, reply) => {
    await fastify.auth0Client!.loginWithCustomTokenExchange(
      {
        subjectToken: 'external-token',
        subjectTokenType: 'urn:acme:legacy-token',
        actorToken: 'actor-token',
        actorTokenType: 'urn:acme:actor-token',
      },
      { request, reply }
    );
    return reply.send({ ok: true });
  });

  await fastify.ready();

  const res = await fastify.inject({ method: 'POST', url: '/test/login-cte-actor' });

  expect(res.statusCode).toBe(200);
  expect(capturedBody['actor_token']).toBe('actor-token');
  expect(capturedBody['actor_token_type']).toBe('urn:acme:actor-token');
});

test('customTokenExchange returns TokenResponse without altering session', async () => {
  const fastify = Fastify();
  fastify.register(plugin, {
    domain: domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    appBaseUrl: 'http://localhost:3000',
    sessionSecret: '<secret>',
  });

  fastify.post('/test/cte', async (request, reply) => {
    const tokenResponse = await fastify.auth0Client!.customTokenExchange(
      {
        subjectToken: 'external-token',
        subjectTokenType: 'urn:acme:legacy-token',
      },
      { request, reply }
    );
    const session = await fastify.auth0Client!.getSession({ request, reply });
    return reply.send({
      accessToken: tokenResponse.accessToken,
      sessionExists: !!session,
    });
  });

  await fastify.ready();

  const res = await fastify.inject({
    method: 'POST',
    url: '/test/cte',
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().accessToken).toBe(accessToken);
  expect(res.json().sessionExists).toBe(false);
});

test('customTokenExchange passes actor token when provided', async () => {
  let capturedBody: Record<string, string> = {};
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
      capturedBody = Object.fromEntries(new URLSearchParams(await request.text()));
      return HttpResponse.json({
        access_token: accessToken,
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

  fastify.post('/test/cte-actor', async (request, reply) => {
    await fastify.auth0Client!.customTokenExchange(
      {
        subjectToken: 'external-token',
        subjectTokenType: 'urn:acme:legacy-token',
        actorToken: 'actor-token',
        actorTokenType: 'urn:acme:actor-token',
      },
      { request, reply }
    );
    return reply.send({ ok: true });
  });

  await fastify.ready();

  const res = await fastify.inject({ method: 'POST', url: '/test/cte-actor' });

  expect(res.statusCode).toBe(200);
  expect(capturedBody['actor_token']).toBe('actor-token');
  expect(capturedBody['actor_token_type']).toBe('urn:acme:actor-token');
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

  const existingStateData: StateData = {
    user: { sub: 'existing-user' },
    idToken: '<existing_id_token>',
    accessToken: '<existing_access_token>',
    refreshToken: '<existing_refresh_token>',
    tokenSets: [],
    internal: { sid: '<sid>', createdAt: 1234567890 },
  };
  const sessionCookieValue = await encrypt(existingStateData, '<secret>', '__a0_session', Date.now() + 10000);

  fastify.post('/test/cte-no-overwrite', async (request, reply) => {
    await fastify.auth0Client!.customTokenExchange(
      {
        subjectToken: 'external-token',
        subjectTokenType: 'urn:acme:legacy-token',
      },
      { request, reply }
    );
    const session = await fastify.auth0Client!.getSession({ request, reply });
    return reply.send({ userSub: session?.user?.sub });
  });

  await fastify.ready();

  const res = await fastify.inject({
    method: 'POST',
    url: '/test/cte-no-overwrite',
    headers: {
      cookie: `__a0_session.0=${sessionCookieValue}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().userSub).toBe('existing-user');
});
