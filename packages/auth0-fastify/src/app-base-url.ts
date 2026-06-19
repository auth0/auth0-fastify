import type {
  FastifyRequest,
  RouteGenericInterface,
  RawServerBase,
  RawServerDefault,
  RawRequestDefaultExpression,
} from 'fastify';
import { InvalidConfigurationError } from './errors/index.js';

/**
 * The normalized form of the `appBaseUrl` option.
 * - `static`: a single fixed base URL.
 * - `allowlist`: infer per request, but the inferred origin must be in `origins`.
 * - `dynamic`: infer per request with no restriction.
 */
export type AppBaseUrlConfig =
  | { mode: 'static'; value: string }
  | { mode: 'allowlist'; origins: Set<string> }
  | { mode: 'dynamic' };

const assertAbsoluteUrl = (value: string): string => {
  try {
    new URL(value);
  } catch {
    throw new InvalidConfigurationError('appBaseUrl must be an absolute URL.');
  }
  return value;
};

/**
 * Validate the `appBaseUrl` option once at plugin init and reduce it to an
 * `AppBaseUrlConfig` the per-request resolver can act on cheaply.
 */
export function normalizeAppBaseUrl(appBaseUrl: string | string[] | undefined): AppBaseUrlConfig {
  if (typeof appBaseUrl === 'string') {
    return { mode: 'static', value: assertAbsoluteUrl(appBaseUrl) };
  }

  if (Array.isArray(appBaseUrl)) {
    if (appBaseUrl.length === 0) {
      throw new InvalidConfigurationError('appBaseUrl must not be an empty array.');
    }
    const origins = new Set(appBaseUrl.map((entry) => new URL(assertAbsoluteUrl(entry)).origin));
    return { mode: 'allowlist', origins };
  }

  return { mode: 'dynamic' };
}

const inferFromRequest = <
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>
>(
  request: FastifyRequest<RouteGenericInterface, RawServer, RawRequest>
): string => {
  const host = request.host;
  if (!host) {
    throw new InvalidConfigurationError('Unable to infer appBaseUrl: missing host.');
  }
  return assertAbsoluteUrl(`${request.protocol}://${host}`);
};

/**
 * Resolve the base URL for the current request based on the normalized config.
 * Throws `InvalidConfigurationError` when inference fails or an inferred origin
 * is not in the allow-list.
 */
export function resolveAppBaseUrl<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>
>(
  config: AppBaseUrlConfig,
  request: FastifyRequest<RouteGenericInterface, RawServer, RawRequest>
): string {
  if (config.mode === 'static') {
    return config.value;
  }

  const inferred = inferFromRequest(request);

  if (config.mode === 'allowlist') {
    const origin = new URL(inferred).origin;
    if (!config.origins.has(origin)) {
      throw new InvalidConfigurationError(
        `The inferred origin "${origin}" is not in the configured appBaseUrl allow-list.`
      );
    }
  }

  return inferred;
}

/**
 * Resolve the effective `secure` flag for the session cookie.
 *
 * When the base URL is dynamic or allow-listed there is no single static
 * protocol to derive `secure` from, so we default it to `true` and forbid an
 * explicit downgrade in production (anti-downgrade). When the base URL is a
 * static string, the configured value passes through unchanged so the caller
 * keeps the existing protocol-based default behavior.
 *
 * @param config The normalized appBaseUrl config.
 * @param configuredSecure The `secure` value the app set, or `undefined` if unset.
 * @param isProduction Whether the process is running in production.
 */
export function resolveSecureCookie(
  config: AppBaseUrlConfig,
  configuredSecure: boolean | undefined,
  isProduction: boolean
): boolean | undefined {
  if (config.mode === 'static') {
    return configuredSecure;
  }

  if (configuredSecure === false) {
    if (isProduction) {
      throw new InvalidConfigurationError(
        'Insecure session cookies (secure: false) are not allowed in production when appBaseUrl is dynamic or an allow-list.'
      );
    }
    return false;
  }

  return true;
}
