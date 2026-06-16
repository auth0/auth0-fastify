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

    return reply.send({ accessToken: tokenResponse.accessToken });
  });

  const res = await fastify.inject({
    method: 'POST',
    url: '/delegate',
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().accessToken).toBe(accessToken);
  expect(res.headers['set-cookie']).toBeUndefined();
});

test('customTokenExchange surfaces the act claim when an actor token is used', async () => {
  server.use(
    http.post(mockOpenIdConfiguration.token_endpoint, async () => {
      return HttpResponse.json({
        access_token: await generateToken(domain, 'user_123', '<client_id>', undefined, undefined, undefined, {
          act: { sub: 'service-account-id' },
        }),
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
