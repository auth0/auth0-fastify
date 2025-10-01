import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { ApiClient } from '@auth0/auth0-api-js';

interface AuthRouteOptions {
  scopes?: string | string[];
}

declare module 'fastify' {
  interface FastifyInstance {
    requireAuth: (opts?: AuthRouteOptions) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    auth0Client: ApiClient | undefined;
  }

  interface FastifyRequest {
    user: Token;

    getToken(): string | undefined;
  }
}

export interface Auth0FastifyApiOptions {
  /**
   * The auth0 domain (without https://)
   */
  domain: string;
  /**
   * The audience for the API
   */
  audience: string;
  /**
   * The optional client ID of the application.
   * Required when using the `getAccessTokenForConnection` method.
   */
  clientId?: string;
  /**
   * The optional client secret of the application.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the `getAccessTokenForConnection` method.
   */
  clientSecret?: string;
  /**
   * The optional client assertion signing key to use.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the `getAccessTokenForConnection` method.
   */
  clientAssertionSigningKey?: string | CryptoKey;
  /**
   * The optional client assertion signing algorithm to use with the `clientAssertionSigningKey`.
   * If not provided, it will default to `RS256`.
   */
  clientAssertionSigningAlg?: string;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
}

export interface Token {
  sub: string;
  aud: string | string[];
  iss: string;
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
async function auth0FastifyApi(fastify: FastifyInstance, options: Auth0FastifyApiOptions) {
  if (!options.audience) {
    throw new Error('In order to use the Auth0 Api plugin, you must provide an audience.');
  }

  const apiClient = new ApiClient({
    domain: options.domain,
    audience: options.audience,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    clientAssertionSigningKey: options.clientAssertionSigningKey,
    clientAssertionSigningAlg: options.clientAssertionSigningAlg,
    customFetch: options.customFetch,
  });

  const replyWithError = (reply: FastifyReply, statusCode: number, error: string, errorDescription: string) => {
    return reply
      .code(statusCode)
      .header(
        'WWW-Authenticate',
        `Bearer error="${error.replaceAll('"', '\\"')}", error_description="${errorDescription.replaceAll('"', '\\"')}"`
      )
      .send({
        error: error,
        error_description: errorDescription,
      });
  };

  fastify.decorate('requireAuth', function (opts: AuthRouteOptions = {}) {
    return async function (request: FastifyRequest, reply: FastifyReply) {
      const accessToken = getToken(request);

      if (!accessToken) {
        return replyWithError(reply, 400, 'invalid_request', 'No Authorization provided');
      }

      try {
        const token = await apiClient.verifyAccessToken({ accessToken }) as Token;

        if (opts.scopes && !validateScopes(token, opts.scopes)) {
          return replyWithError(reply, 403, 'insufficient_scope', 'Insufficient scopes');
        }

        request['user'] = token;
      } catch (error) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if ((error as any).code === 'verify_access_token_error') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          return replyWithError(reply, 401, 'invalid_token', (error as any).message);
        }

        return replyWithError(reply, 401, 'invalid_token', 'Invalid token');
      }
    };
  });

  fastify.decorateRequest('getToken', function () {
    return getToken(this);
  });

  fastify.decorate('auth0Client', apiClient);
}


export default fp(auth0FastifyApi);

function getToken(request: FastifyRequest): string | undefined {
  const parts = request.headers.authorization?.split(' ');

  return parts?.length === 2 && parts[0]?.toLowerCase() === 'bearer' ? parts[1] : undefined;
}
