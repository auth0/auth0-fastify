import { CookieSerializeOptions } from '@fastify/cookie';
import { AbstractTransactionStore, TransactionData } from '@auth0/auth0-server-js';
import { MissingStoreOptionsError } from '../errors/index.js';
import { StoreOptions } from '../types.js';

export class CookieTransactionStore extends AbstractTransactionStore<StoreOptions> {
  async set(identifier: string, transactionData: TransactionData, removeIfExists?: boolean, options?: StoreOptions): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const maxAge = 60 * 60;
    const cookieOpts: CookieSerializeOptions = { httpOnly: true, sameSite: 'lax', path: '/', maxAge };
    const expiration = Math.floor((Date.now() / 1000) + maxAge);
    const encryptedTransactionData = await this.encrypt(identifier, transactionData, expiration);

    options.reply.setCookie(identifier, encryptedTransactionData, cookieOpts);
  }

  async get(identifier: string, options?: StoreOptions): Promise<TransactionData | undefined> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    const encryptedTransactionData = options.request.cookies[identifier];
    if (encryptedTransactionData) {
      return (await this.decrypt(identifier, encryptedTransactionData)) as TransactionData;
    }
  }

  async delete(identifier: string, options?: StoreOptions | undefined): Promise<void> {
    // We can not handle cookies in Fastify when the `StoreOptions` are not provided.
    if (!options) {
      throw new MissingStoreOptionsError();
    }

    options?.reply.clearCookie(identifier);
  }
}
