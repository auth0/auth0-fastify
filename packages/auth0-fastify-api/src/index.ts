import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import {
  ApiClient,
  type ApiClientOptions,
  type DiscoveryCacheOptions,
  type DomainsResolver,
  type VerifyAccessTokenOptions,
} from '@auth0/auth0-api-js';

export type AuthRouteOptions = {
  scopes?: string | string[];
};

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

type Auth0FastifyApiCommonOptions = {
  /**
   * The audience for the API
   */
  audience: string;
  /**
   * Optional list of allowed JWT algorithms for access token verification.
   * Defaults to ['RS256'] when not provided. HS* values are rejected.
   */
  algorithms?: string[];
  /**
   * The optional client ID of the application.
   * Required when using the `getAccessTokenForConnection` method.
   */
  clientId?: string;
  /**
   * The optional client secret of the application.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the
   * `getAccessTokenForConnection` method.
   */
  clientSecret?: string;
  /**
   * The optional client assertion signing key to use.
   * At least one of `clientSecret` or `clientAssertionSigningKey` is required when using the
   * `getAccessTokenForConnection` method.
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
  /**
   * Optional discovery cache configuration for OIDC metadata and JWKS fetchers.
   * TTL is in seconds. Defaults to the ApiClient defaults when omitted.
   */
  discoveryCache?: DiscoveryCacheOptions;
};

export type Auth0FastifyApiOptions =
  | (Auth0FastifyApiCommonOptions & {
      /**
       * The auth0 domain (without https://)
       */
      domain: string;
      /**
       * Optional domain allowlist or resolver for access token verification.
       * When provided, token verification uses this instead of `domain`.
       * Provide domains as shown in the Auth0 Dashboard (for example, "example.auth0.com").
       * The underlying ApiClient also normalizes equivalent `https://` values without path, query, or fragment.
       */
      domains?: string[] | DomainsResolver;
    })
  | (Auth0FastifyApiCommonOptions & {
      /**
       * Domain allowlist or resolver for access token verification.
       * Provide domains as shown in the Auth0 Dashboard (for example, "example.auth0.com").
       * The underlying ApiClient also normalizes equivalent `https://` values without path, query, or fragment.
       */
      domains: string[] | DomainsResolver;
      domain?: never;
      clientId?: never;
      clientSecret?: never;
      clientAssertionSigningKey?: never;
      clientAssertionSigningAlg?: never;
    });

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

function hasDomain(options: Auth0FastifyApiOptions): options is Extract<Auth0FastifyApiOptions, { domain: string }> {
  return typeof (options as { domain?: unknown }).domain === 'string';
}

type ApiClientBaseOptions = {
  audience: ApiClientOptions['audience'];
  algorithms?: ApiClientOptions['algorithms'];
  customFetch?: ApiClientOptions['customFetch'];
  discoveryCache?: ApiClientOptions['discoveryCache'];
};

async function auth0FastifyApi(fastify: FastifyInstance, options: Auth0FastifyApiOptions) {
  if (!options.audience) {
    throw new Error('In order to use the Auth0 Api plugin, you must provide an audience.');
  }

  const baseClientOptions: ApiClientBaseOptions = {
    audience: options.audience,
    algorithms: options.algorithms,
    customFetch: options.customFetch,
    discoveryCache: options.discoveryCache,
  };

  const clientOptions: ApiClientOptions = hasDomain(options)
    ? {
        ...baseClientOptions,
        domain: options.domain,
        domains: options.domains,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        clientAssertionSigningKey: options.clientAssertionSigningKey,
        clientAssertionSigningAlg: options.clientAssertionSigningAlg,
      }
    : {
        ...baseClientOptions,
        domains: options.domains,
      };

  const apiClient = new ApiClient(clientOptions);

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
        const verifyOptions: VerifyAccessTokenOptions = options.domains
          ? {
              accessToken,
              httpUrl: buildRequestUrl(request),
              headers: request.headers as Record<string, string | string[] | undefined>,
            }
          : {
              accessToken,
            };

        const token = (await apiClient.verifyAccessToken(verifyOptions)) as Token;

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

function buildRequestUrl(request: FastifyRequest): string | undefined {
  if (!request.host || !request.protocol) {
    return undefined;
  }

  return `${request.protocol}://${request.host}${request.url}`;
}

export type { DomainsResolver, DomainsResolverContext } from '@auth0/auth0-api-js';
