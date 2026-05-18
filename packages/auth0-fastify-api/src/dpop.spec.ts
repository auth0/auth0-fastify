import { expect, test, afterAll, afterEach, beforeAll, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JWK } from 'jose';
import Fastify from 'fastify';
import fastifyAuth0Api, { InvalidDpopProofError, InvalidRequestError, VerifyAccessTokenError } from './index.js';

const issuer = 'https://dpop-test.auth0.local/';
const audience = 'https://api.example.com';

const discoveryUrl = `${issuer}.well-known/openid-configuration`;
const jwksUrl = `${issuer}.well-known/jwks.json`;
const domain = 'dpop-test.auth0.local';

let rsaPrivateKey: CryptoKey;
let rsaPublicJwk: JWK;
let ecPrivateKey: CryptoKey;
let ecPublicJwk: JWK;
let ecThumbprint: string;

const handlers = [
  http.get(discoveryUrl, () =>
    HttpResponse.json({
      issuer,
      jwks_uri: jwksUrl,
      token_endpoint: `${issuer}oauth/token`,
    })
  ),
  http.get(jwksUrl, () => HttpResponse.json({ keys: [rsaPublicJwk] })),
];

const server = setupServer(...handlers);

beforeAll(async () => {
  const rsa = await generateKeyPair('RS256');
  rsaPrivateKey = rsa.privateKey;
  rsaPublicJwk = await exportJWK(rsa.publicKey);
  (rsaPublicJwk as Record<string, unknown>).alg = 'RS256';

  const ec = await generateKeyPair('ES256');
  ecPrivateKey = ec.privateKey;
  ecPublicJwk = await exportJWK(ec.publicKey);
  (ecPublicJwk as Record<string, unknown>).alg = 'ES256';
  ecThumbprint = await calculateJwkThumbprint(ecPublicJwk);

  server.listen({ onUnhandledRequest: 'error' });
});

afterAll(() => server.close());
afterEach(() => server.resetHandlers());

async function computeAth(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function signAccessToken(opts?: { cnfJkt?: string; claims?: Record<string, unknown> }): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    ...(opts?.claims || {}),
    ...(opts?.cnfJkt ? { cnf: { jkt: opts.cnfJkt } } : {}),
  };

  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .setSubject('user_123')
    .sign(rsaPrivateKey);
}

async function createDpopProof(
  accessToken: string,
  method: string,
  url: string,
  opts?: { invalidAth?: boolean; expiredIat?: boolean }
): Promise<string> {
  const ath = opts?.invalidAth ? 'bad-ath-value' : await computeAth(accessToken);
  const iat = opts?.expiredIat ? Math.floor(Date.now() / 1000) - 600 : Math.floor(Date.now() / 1000);

  return new SignJWT({
    htm: method,
    htu: url,
    iat,
    jti: crypto.randomUUID(),
    ath,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: ecPublicJwk })
    .sign(ecPrivateKey);
}

// ---------------------------------------------------------------------------
// DPoP mode: 'allowed' (default)
// ---------------------------------------------------------------------------

describe('DPoP mode: allowed (default)', () => {
  test('should accept a valid Bearer token without DPoP proof', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken();
    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `Bearer ${accessToken}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('OK');
  });

  test('should accept a valid DPoP-bound token with valid proof', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('OK');
  });

  test('should reject DPoP-bound token presented with Bearer scheme', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `Bearer ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_token');
  });

  test('should reject DPoP scheme with invalid proof (bad ath)', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test', { invalidAth: true });

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_dpop_proof');
  });

  test('should reject DPoP scheme without proof in allowed mode', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `DPoP ${accessToken}` },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  test('should reject DPoP scheme when token has no cnf.jkt', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken();
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_token');
  });

  test('should include WWW-Authenticate with DPoP challenge', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test', { invalidAth: true });

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    const wwwAuth = res.headers['www-authenticate'];
    expect(wwwAuth).toBeDefined();
    expect(String(wwwAuth)).toMatch(/DPoP/);
    expect(String(wwwAuth)).toMatch(/algs="ES256"/);
  });
});

// ---------------------------------------------------------------------------
// DPoP mode: 'required'
// ---------------------------------------------------------------------------

describe('DPoP mode: required', () => {
  test('should reject Bearer token when DPoP is required', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'required' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken();

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `Bearer ${accessToken}` },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
    const wwwAuth = res.headers['www-authenticate'];
    expect(wwwAuth).toBeDefined();
    expect(String(wwwAuth)).toMatch(/DPoP/);
    expect(String(wwwAuth)).toMatch(/algs="ES256"/);
  });

  test('should accept valid DPoP token when DPoP is required', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'required' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('OK');
  });

  test('should reject DPoP scheme without proof when DPoP is required', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'required' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `DPoP ${accessToken}` },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  test('should only include DPoP challenge (not Bearer) when mode is required', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'required' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken();

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `Bearer ${accessToken}` },
    });

    const wwwAuth = String(res.headers['www-authenticate']);
    expect(wwwAuth).toMatch(/DPoP/);
    expect(wwwAuth).not.toMatch(/Bearer realm=/);
  });

  test('should reject invalid DPoP proof when mode is required', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'required' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test', { invalidAth: true });

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_dpop_proof');
  });
});

// ---------------------------------------------------------------------------
// DPoP mode: 'disabled'
// ---------------------------------------------------------------------------

describe('DPoP mode: disabled', () => {
  test('should accept Bearer token when DPoP is disabled', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'disabled' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken();

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `Bearer ${accessToken}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('OK');
  });

  test('should reject DPoP scheme when DPoP is disabled', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'disabled' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  test('should only include Bearer challenge (not DPoP) when mode is disabled', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { mode: 'disabled' } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    const wwwAuth = String(res.headers['www-authenticate']);
    expect(wwwAuth).toMatch(/Bearer/);
    expect(wwwAuth).not.toMatch(/DPoP algs=/);
  });
});

// ---------------------------------------------------------------------------
// DPoP proof validation details
// ---------------------------------------------------------------------------

describe('DPoP proof validation', () => {
  test('should reject proof with wrong HTTP method', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.post('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'POST',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_dpop_proof');
  });

  test('should reject proof with wrong URL', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/correct-path', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/wrong-path');

    const res = await fastify.inject({
      method: 'GET',
      url: '/correct-path',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_dpop_proof');
  });

  test('should reject proof with expired iat', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { iatOffset: 60 } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test', { expiredIat: true });

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_dpop_proof');
  });

  test('should validate proof with custom iatOffset and iatLeeway', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience, dpop: { iatOffset: 700, iatLeeway: 60 } });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test', { expiredIat: true });

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('OK');
  });
});

// ---------------------------------------------------------------------------
// DPoP with scope validation
// ---------------------------------------------------------------------------

describe('DPoP with scope validation', () => {
  test('should enforce scopes with DPoP-bound tokens', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth({ scopes: 'admin:write' }) }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint, claims: { scope: 'read:data' } });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('insufficient_scope');
  });

  test('should pass scope validation with DPoP-bound tokens', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth({ scopes: 'read:data' }) }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint, claims: { scope: 'read:data write:data' } });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('OK');
  });
});

// ---------------------------------------------------------------------------
// DPoP with Multiple Custom Domains
// ---------------------------------------------------------------------------

describe('DPoP with Multiple Custom Domains', () => {
  test('should validate DPoP with domains allowlist', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { audience, domains: [domain] });

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async () => 'OK');
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('OK');
  });
});

// ---------------------------------------------------------------------------
// getToken() with DPoP scheme
// ---------------------------------------------------------------------------

describe('getToken() with DPoP scheme', () => {
  test('should extract token from DPoP Authorization header', async () => {
    const fastify = Fastify();
    fastify.register(fastifyAuth0Api, { domain, audience });

    let extractedToken: string | undefined;

    fastify.register(() => {
      fastify.get('/test', { preHandler: fastify.requireAuth() }, async (request) => {
        extractedToken = request.getToken();
        return 'OK';
      });
    });

    const accessToken = await signAccessToken({ cnfJkt: ecThumbprint });
    const dpopProof = await createDpopProof(accessToken, 'GET', 'http://localhost:80/test');

    const res = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: dpopProof,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(extractedToken).toBe(accessToken);
  });
});

// ---------------------------------------------------------------------------
// Error class exports
// ---------------------------------------------------------------------------

describe('DPoP error class exports', () => {
  test('InvalidDpopProofError is exported', () => {
    expect(InvalidDpopProofError).toBeDefined();
    const err = new InvalidDpopProofError('test');
    expect(err.code).toBe('invalid_dpop_proof');
    expect(err.statusCode).toBe(400);
  });

  test('InvalidRequestError is exported', () => {
    expect(InvalidRequestError).toBeDefined();
    const err = new InvalidRequestError('test');
    expect(err.code).toBe('invalid_request');
    expect(err.statusCode).toBe(400);
  });

  test('VerifyAccessTokenError is exported', () => {
    expect(VerifyAccessTokenError).toBeDefined();
    const err = new VerifyAccessTokenError('test');
    expect(err.code).toBe('verify_access_token_error');
    expect(err.statusCode).toBe(401);
  });
});
