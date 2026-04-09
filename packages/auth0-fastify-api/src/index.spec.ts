import { expect, test, afterAll, afterEach, beforeAll } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from './test-utils/tokens.js';
import Fastify from 'fastify';
import fastifyAuth0Api from './index.js';

const createOpenIdConfiguration = (domain: string) => ({
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
});

const domain = 'auth0.local';
const secondaryDomain = 'custom.local';
let mockOpenIdConfiguration = createOpenIdConfiguration(domain);

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),
  http.post(`https://${domain}/custom/token`, async () => {
    const accessToken = await generateToken(domain, 'user_123');
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

afterEach(() => {
  mockOpenIdConfiguration = createOpenIdConfiguration(domain);
  server.resetHandlers();
});

const addHandlersForDomain = (targetDomain: string) => {
  const config = createOpenIdConfiguration(targetDomain);
  server.use(
    http.get(`https://${targetDomain}/.well-known/openid-configuration`, () => {
      return HttpResponse.json(config);
    }),
    http.get(`https://${targetDomain}/.well-known/jwks.json`, () => {
      return HttpResponse.json({ keys: jwks });
    }),
    http.post(`https://${targetDomain}/custom/token`, async () => {
      const accessToken = await generateToken(targetDomain, 'user_123');
      return HttpResponse.json({
        access_token: accessToken,
        id_token: await generateToken(targetDomain, 'user_123', '<client_id>'),
        expires_in: 60,
        token_type: 'Bearer',
      });
    })
  );
};

test('should return 400 when no token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
  });

  expect(res.statusCode).toBe(400);
  expect(res.json().error).toBe('invalid_request');
  expect(res.json().error_description).toBe('No Authorization provided');
});

test('should return 200 when valid token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should return 401 when no issuer in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', undefined, false);

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "iss" claim');
});

test('should return 401 when invalid issuer in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', 'https://invalid-issuer.local');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('unexpected "iss" claim value');
});

test('should return 401 when no audience in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "aud" claim');
});

test('should return 401 when no iat in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, false, undefined, {
    scope: 'valid',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "iat" claim');
});

test('should return 401 when no exp in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, false);

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('missing required "exp" claim');
});

test('should return 401 when invalid audience in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<invalid_audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toBe('unexpected "aud" claim value');
});

test('should throw when no audience configured', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  await expect(
    fastify.inject({
      method: 'GET',
      url: '/test',
    })
  ).rejects.toThrowError('In order to use the Auth0 Api plugin, you must provide an audience.');
});

test('should return 403 when invalid scope in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
    scope: 'invalid',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth({ scopes: 'valid' }),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(403);
  expect(res.json().error).toBe('insufficient_scope');
  expect(res.json().error_description).toBe('Insufficient scopes');
});

test('should return 200 when valid audience in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should return 200 when valid scope in token', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>', undefined, undefined, undefined, {
    scope: 'valid',
  });

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth({ scopes: 'valid' }),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should verify token with domains allowlist (no domain)', async () => {
  addHandlersForDomain(secondaryDomain);

  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: [secondaryDomain],
  });

  const accessToken = await generateToken(secondaryDomain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should pass request url and headers to domains resolver', async () => {
  addHandlersForDomain(secondaryDomain);

  let resolvedContext: {
    url?: string;
    headers?: Record<string, string | string[] | undefined>;
    unverifiedIss?: string;
  } | undefined;

  const fastify = Fastify({ trustProxy: true });
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: (context) => {
      resolvedContext = context;
      return [secondaryDomain];
    },
  });

  const accessToken = await generateToken(secondaryDomain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test?mode=1',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'x-forwarded-host': 'api.example.com',
      'x-forwarded-proto': 'https',
    },
  });

  expect(res.statusCode).toBe(200);
  expect(resolvedContext?.url).toBe('https://api.example.com/test?mode=1');
  expect(resolvedContext?.headers?.['x-forwarded-host']).toBe('api.example.com');
});

test('should return 401 when domains resolver returns invalid domain', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: () => ['https://invalid.example.com/path'],
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toMatch(/path segments are not allowed/i);
});

test('should reject HS* algorithms in configuration', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    algorithms: ['HS256'],
  });

  await expect(fastify.ready()).rejects.toThrow(/Invalid algorithms configuration/);
});

test('should accept discoveryCache configuration', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    domain: domain,
    audience: '<audience>',
    discoveryCache: { ttl: 1, maxEntries: 1 },
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toBe('OK');
});

test('should return 401 when domains resolver throws', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: () => {
      throw new Error('resolver failed');
    },
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toMatch(/domains resolver failed/i);
});

test('should return 401 when domains resolver returns empty list', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: () => [],
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toMatch(/returned no allowed domains/i);
});

test('should return 401 when domains resolver returns non-string domain', async () => {
  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    domains: () => ['valid.example.com', 123 as any],
  });

  const accessToken = await generateToken(domain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toMatch(/non-string domain/i);
});

test('should return 401 when token is missing iss with domains enabled', async () => {
  addHandlersForDomain(secondaryDomain);

  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: [secondaryDomain],
  });

  const accessToken = await generateToken(secondaryDomain, 'user_123', '<audience>', false);

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toMatch(/missing required "iss" claim/i);
});

test('should return 401 when issuer not in resolved domains list', async () => {
  addHandlersForDomain(secondaryDomain);

  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: () => ['other.example.com'],
  });

  const accessToken = await generateToken(secondaryDomain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });

  expect(res.statusCode).toBe(401);
  expect(res.json().error).toBe('invalid_token');
  expect(res.json().error_description).toMatch(/issuer is not in the configured domain list/i);
});

test('should ignore x-forwarded-host and x-forwarded-proto when trustProxy is disabled', async () => {
  addHandlersForDomain(secondaryDomain);

  let resolvedContext: {
    url?: string;
  } | undefined;

  const fastify = Fastify();
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: (context) => {
      resolvedContext = context;
      return [secondaryDomain];
    },
  });

  const accessToken = await generateToken(secondaryDomain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test?x=1',
    headers: {
      authorization: `Bearer ${accessToken}`,
      host: 'internal.local',
      'x-forwarded-host': 'api.forwarded.example.com',
      'x-forwarded-proto': 'https',
    },
  });

  expect(res.statusCode).toBe(200);
  expect(resolvedContext?.url).toBe('http://internal.local/test?x=1');
});

test('should use x-forwarded-host and x-forwarded-proto when trustProxy is enabled', async () => {
  addHandlersForDomain(secondaryDomain);

  let resolvedContext: {
    url?: string;
  } | undefined;

  const fastify = Fastify({ trustProxy: true });
  fastify.register(fastifyAuth0Api, {
    audience: '<audience>',
    domains: (context) => {
      resolvedContext = context;
      return [secondaryDomain];
    },
  });

  const accessToken = await generateToken(secondaryDomain, 'user_123', '<audience>');

  fastify.register(() => {
    fastify.get(
      '/test',
      {
        preHandler: fastify.requireAuth(),
      },
      async () => {
        return 'OK';
      }
    );
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test?x=1',
    headers: {
      authorization: `Bearer ${accessToken}`,
      host: 'internal.local',
      'x-forwarded-host': 'api.forwarded.example.com',
      'x-forwarded-proto': 'https',
    },
  });

  expect(res.statusCode).toBe(200);
  expect(resolvedContext?.url).toBe('https://api.forwarded.example.com/test?x=1');
});
