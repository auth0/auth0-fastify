import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { ApiClient } from '@auth0/auth0-auth-js';

export * from './types.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

interface AuthRouteOptions {
  scopes?: string | string[];
}

declare module 'fastify' {
  interface FastifyInstance {
    requireAuth: (opts?: AuthRouteOptions) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    user: Token;
  }
}

export interface Auth0FastifyJwtOptions {
  domain: string;
  audience: string;
}

interface Token {
  sub?: string;
  aud?: string | string[];
  iss?: string;
  scope?: string;
}

function validateScopes(token: Token, requiredScopes: string | string[]): boolean {
  const scopes = Array.isArray(requiredScopes) ? requiredScopes : [requiredScopes];

  // Extract token scopes (handling different formats)
  let tokenScopes: string[] = [];

  if (token.scope) {
    tokenScopes = typeof token.scope === 'string' ? token.scope.split(' ') : token.scope;
  }

  // All required scopes must be present
  return scopes.every((required) => tokenScopes.includes(required));
}

export default fp(async function auth0FastifJwt(fastify: FastifyInstance, options: Auth0FastifyJwtOptions) {
  if (!options.audience) {
    throw new Error('In order to use the Auth0 JWT plugin, you must provide an audience.');
  }

  const apiClient = new ApiClient({
    domain: options.domain,
    audience: options.audience,
  });

  fastify.decorate('requireAuth', function (opts: AuthRouteOptions = {}) {
    return async function (request: FastifyRequest, reply: FastifyReply) {
      const rawToken = getToken(request);

      if (!rawToken) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'No Authorization provided',
        });
      }

      try {
        const token: Token = await apiClient.verifyAccessToken(rawToken);
        if (opts.scopes && !validateScopes(token, opts.scopes)) {
          return reply.code(403).send({
            error: 'Forbidden',
            message: 'Insufficient scopes',
          });
        }

        request['user'] = token;
      } catch (error) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if ((error as any).code === 'verify_access_token_error') {
          return reply.code(401).send({
            error: 'Unauthorized',
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            message: (error as any).message,
          });
        }

        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Invalid token',
        });
      };
    };
  });
});

function getToken(request: FastifyRequest): string | undefined {
  if (request.headers.authorization && /^Bearer\s/i.test(request.headers.authorization)) {
    const parts = request.headers.authorization.split(' ');
    if (parts.length === 2) {
      return parts[1];
    }
  }
}
