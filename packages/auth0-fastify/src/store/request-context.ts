import { AsyncLocalStorage } from 'node:async_hooks';
import { StoreOptions } from '../types.js';
import { RawReplyDefaultExpression, RawRequestDefaultExpression, RawServerBase } from 'fastify';

/**
 * Context containing Express request and response objects.
 * Available within the AsyncLocalStorage scope established by the auth0 middleware.
 */
export type RequestContext = StoreOptions;

/**
 * AsyncLocalStorage instance for storing request context.
 * @internal
 */
const asyncLocalStorage = new AsyncLocalStorage<unknown>();

/**
 * Runs a callback within an AsyncLocalStorage context containing the request and response.
 * This establishes the context for the entire request lifecycle.
 *
 * @param request - Express request object
 * @param response - Express response object
 * @param callback - Function to execute within the context
 * @returns The result of the callback
 *
 * @example
 * ```typescript
 * app.use((req, res, next) => {
 *   runWithContext(req, res, () => next());
 * });
 * ```
 */
export function runWithContext<T, TRequestContext>(context: TRequestContext, callback: () => T): T {
  return asyncLocalStorage.run(context, callback);
}

/**
 * Retrieves the current request context from AsyncLocalStorage.
 *
 * @returns The current RequestContext
 * @throws {Error} If called outside of a request context
 *
 * @example
 * ```typescript
 * const { request, response } = getRequestContext();
 * ```
 */
export function getRequestContext<
  TRawServer extends RawServerBase,
  TRawRequest extends RawRequestDefaultExpression<TRawServer>,
  TRawReply extends RawReplyDefaultExpression<TRawServer>,
>(): StoreOptions<TRawServer, TRawRequest, TRawReply> {
  const context = asyncLocalStorage.getStore();

  if (!context) {
    throw new Error(
      'Request context not available. This error typically occurs when:\n' +
        '1. Client methods are called outside of a request handler\n' +
        '2. The auth0 SDK has not been initialized\n' +
        '3. AsyncLocalStorage context was lost in an async operation\n\n' +
        'Ensure you are calling client methods within a Fastify request handler ' +
        'and the auth0 SDK is properly configured.'
    );
  }

  return context as StoreOptions<TRawServer, TRawRequest, TRawReply>;
}
