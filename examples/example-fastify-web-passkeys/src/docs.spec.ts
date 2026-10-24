// The code in the "Login and Signup using Passkeys" section of the Fastify EXAMPLES.md is code that people copy. This
// checks that its schemas and browser helpers are the ones of this example, and runs the two snippets that nothing
// else tests: the browser flow and the Origin check. The routes in that section are checked by passkey.spec.ts of the
// package.
import { readFileSync } from 'node:fs';
import Fastify from 'fastify';
import { describe, expect, test } from 'vitest';

const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');

const docs = read('../../../packages/auth0-fastify/EXAMPLES.md');
const section = docs.slice(
  docs.indexOf('\n## Login and Signup using Passkeys\n'),
  docs.indexOf('\n## Login using Custom Token Exchange\n')
);

/** The fenced code blocks of the section. A block inside a list item loses the indentation of the list item. */
function codeBlocks(markdown: string): string[] {
  const blocks: string[] = [];
  const lines = markdown.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const open = /^(\s*)```\w*$/.exec(lines[i] ?? '');
    if (!open) {
      continue;
    }
    const indent = open[1] ?? '';
    const body: string[] = [];
    for (i++; i < lines.length && lines[i] !== `${indent}\`\`\``; i++) {
      const line = lines[i] ?? '';
      body.push(line.startsWith(indent) ? line.slice(indent.length) : line);
    }
    blocks.push(body.join('\n'));
  }
  return blocks;
}

const blocks = codeBlocks(section);
const block = (contains: string) => {
  const found = blocks.find((text) => text.includes(contains));
  if (!found) {
    throw new Error(`No code block with "${contains}" in the passkeys section of EXAMPLES.md`);
  }
  return found;
};

describe('the code in the docs is the code of this example', () => {
  test('the schemas', () => {
    const source = read('./passkey.ts');
    const schemas = source
      .slice(source.indexOf('export type SignupBody'), source.indexOf('export interface CompleteFailure'))
      .replace(/^export /gm, '')
      .trimEnd();

    expect(block('const signupBody')).toContain(schemas);
  });

  test('the browser helpers', () => {
    const source = read('../public/webauthn.js');
    const helpers = source
      .slice(source.indexOf('// Auth0 sends binary values'), source.indexOf('// A sentence for an error'))
      .replace(/^export /gm, '')
      .trimEnd();

    expect(block('function creationOptions')).toBe(helpers);
  });
});

// ─── The browser flow ─────────────────────────────────────────────────────────────────────────

const bytes = (...values: number[]) => Uint8Array.from(values).buffer;
const bytesOf = (value: ArrayBuffer) => [...new Uint8Array(value)];

const credentialOf = (kind: 'attestation' | 'assertion') => ({
  id: 'cred-id',
  rawId: bytes(1, 2, 3),
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response:
    kind === 'attestation'
      ? { clientDataJSON: bytes(4, 5), attestationObject: bytes(6) }
      : { clientDataJSON: bytes(4, 5), authenticatorData: bytes(7), signature: bytes(8), userHandle: bytes(9) },
  getClientExtensionResults: () => ({}),
});

type Codes = Record<string, string>;
interface Flow {
  loginWithPasskey: () => Promise<Record<string, unknown>>;
  signUpWithPasskey: (profile: Record<string, string>) => Promise<Record<string, unknown>>;
}

/** The flow of the docs, run against a scripted server and a fake authenticator, with the page's own UI stubbed. */
function world({ answers, codes = [] }: { answers: Array<[number, unknown]>; codes?: Codes[] }) {
  const events: string[] = [];
  const asked: string[][] = [];
  const calls: Array<{ path: string; body: Record<string, any> }> = [];
  const publicKeys: Array<Record<string, any>> = [];

  const fetch = async (path: string, init: { method: string; headers: Record<string, string>; body: string }) => {
    expect(init.method).toBe('POST');
    expect(init.headers['content-type']).toBe('application/json');
    calls.push({ path, body: JSON.parse(init.body) });
    const [status, data] = answers.shift() ?? [500, {}];
    return { status, json: async () => data };
  };
  const navigator = {
    credentials: {
      create: async ({ publicKey }: { publicKey: Record<string, any> }) => {
        events.push('create');
        publicKeys.push(publicKey);
        return credentialOf('attestation');
      },
      get: async ({ publicKey }: { publicKey: Record<string, any> }) => {
        events.push('get');
        publicKeys.push(publicKey);
        return credentialOf('assertion');
      },
    },
  };
  const askForCodes = async (identifiers: string[]) => {
    events.push('codes');
    asked.push(identifiers);
    return codes.shift();
  };

  const code = `${block('function creationOptions')}\n${block('function loginWithPasskey')}
    return { loginWithPasskey, signUpWithPasskey };`;
  const flow = new Function('fetch', 'navigator', 'askForCodes', code)(fetch, navigator, askForCodes) as Flow;

  return { ...flow, events, asked, calls, publicKeys };
}

const signupStart = (verificationRequired: string[]): [number, unknown] => [
  200,
  { authnParamsPublicKey: { challenge: 'AQID', user: { id: 'BAU', name: 'a@b.c' } }, verificationRequired },
];

describe('the browser flow in the docs', () => {
  test('a login decodes the options, serializes the credential and sends no codes', async () => {
    const w = world({
      answers: [
        [200, { authnParamsPublicKey: { challenge: 'AQID', allowCredentials: [{ type: 'public-key', id: 'BAU' }] } }],
        [200, { status: 'complete' }],
      ],
    });

    expect(await w.loginWithPasskey()).toEqual({ httpStatus: 200, status: 'complete' });
    expect(bytesOf(w.publicKeys[0]?.challenge)).toEqual([1, 2, 3]);
    expect(bytesOf(w.publicKeys[0]?.allowCredentials[0].id)).toEqual([4, 5]);
    expect(w.calls.map((call) => call.path)).toEqual(['/api/passkey/login/start', '/api/passkey/complete']);
    expect(w.calls[1]?.body).toEqual({
      credential: {
        id: 'cred-id',
        rawId: 'AQID',
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: { clientDataJSON: 'BAU', authenticatorData: 'Bw', signature: 'CA', userHandle: 'CQ' },
        clientExtensionResults: {},
      },
    });
  });

  test('a signup asks for the codes before the passkey, and a wrong code asks again with the same credential', async () => {
    const w = world({
      answers: [
        signupStart(['email', 'phone']),
        [400, { status: 'retry', verificationRequired: ['phone'] }],
        [200, { status: 'complete' }],
      ],
      codes: [{ email: '111111', phone: '222222' }, { phone: '333333' }],
    });

    expect(await w.signUpWithPasskey({ email: 'a@b.c', phoneNumber: '+14155550100' })).toEqual({
      httpStatus: 200,
      status: 'complete',
    });
    expect(w.events).toEqual(['codes', 'create', 'codes']);
    expect(w.asked).toEqual([['email', 'phone'], ['phone']]);
    expect(w.calls[0]).toEqual({
      path: '/api/passkey/signup/start',
      body: { email: 'a@b.c', phoneNumber: '+14155550100' },
    });
    expect(bytesOf(w.publicKeys[0]?.challenge)).toEqual([1, 2, 3]);
    expect(bytesOf(w.publicKeys[0]?.user.id)).toEqual([4, 5]);
    expect(w.calls[1]?.body.verification).toEqual({ email: '111111', phone: '222222' });
    expect(w.calls[2]?.body.verification).toEqual({ phone: '333333' });
    expect(w.calls[2]?.body.credential).toEqual(w.calls[1]?.body.credential);
    expect(w.calls[1]?.body.credential.response.attestationObject).toBe('Bg');
  });

  test('a retry without a list asks for the same identifiers again', async () => {
    const w = world({
      answers: [
        signupStart(['email']),
        [400, { status: 'retry', verificationRequired: [] }],
        [200, { status: 'complete' }],
      ],
      codes: [{ email: '111111' }, { email: '222222' }],
    });

    await w.signUpWithPasskey({ email: 'a@b.c' });

    expect(w.asked).toEqual([['email'], ['email']]);
    expect(w.calls[2]?.body.verification).toEqual({ email: '222222' });
  });

  test('a signup without codes sends no verification, and any other status goes back to the caller', async () => {
    const w = world({ answers: [signupStart([]), [429, { status: 'wait' }]] });

    expect(await w.signUpWithPasskey({ email: 'a@b.c' })).toEqual({ httpStatus: 429, status: 'wait' });
    expect(w.events).toEqual(['create']);
    expect(w.calls[1]?.body).not.toHaveProperty('verification');
  });

  test.each([
    ['signup', 'passkey_register_error'],
    ['login', 'passkey_challenge_error'],
  ])('a %s that Auth0 refused is returned to the caller, and no passkey prompt opens', async (kind, code) => {
    const refusal = { statusCode: 400, code, message: 'The user already exists.' };
    const w = world({ answers: [[400, refusal]] });

    const result = kind === 'signup' ? await w.signUpWithPasskey({ email: 'a@b.c' }) : await w.loginWithPasskey();

    expect(result).toEqual({ httpStatus: 400, ...refusal });
    expect(w.events).toEqual([]);
  });
});

// ─── The Origin check ─────────────────────────────────────────────────────────────────────────

describe('the Origin check in the docs', () => {
  const hook = block('fastify.addHook').replace('<APP_BASE_URL>', 'http://localhost:3000');

  test.each([
    ['no Origin header', '/api/passkey/login/start', {}, 403],
    ['another origin', '/api/passkey/login/start', { origin: 'https://evil.example' }, 403],
    ['a percent-encoded path', '/%61pi/passkey/login/start', {}, 403],
    ['the app origin', '/api/passkey/login/start', { origin: 'http://localhost:3000' }, 200],
    ['a route outside /api/, like a server-to-server call', '/auth/backchannel-logout', {}, 200],
  ])('a POST with %s', async (_label, url, headers, status) => {
    const fastify = Fastify();
    new Function('fastify', hook)(fastify);
    fastify.post('/api/passkey/login/start', async () => ({ ok: true }));
    fastify.post('/auth/backchannel-logout', async () => ({ ok: true }));

    const res = await fastify.inject({
      method: 'POST',
      url,
      payload: '{}',
      headers: { ...headers, 'content-type': 'text/plain' },
    });

    expect(res.statusCode).toBe(status);
  });
});
