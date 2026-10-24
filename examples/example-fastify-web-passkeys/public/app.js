// The browser half of the example. It never sees the Auth0 authSession: the SDK keeps it in the HttpOnly
// __a0_passkey_tx cookie. The page only gets the WebAuthn options and the identifiers to verify, and sends back the
// passkey and the one-time codes.
import { creationOptions, requestOptions, serialize, webauthnMessage } from './webauthn.js';

const $ = (id) => document.getElementById(id);
const card = $('card');
const webauthn = typeof window.PublicKeyCredential === 'function';

// Wrong-code retries per signup. Auth0 limits wrong codes too, but does not say how many are left.
const MAX_RETRIES = 5;

// ─── Server calls ───────────────────────────────────────────────────────────

/** POSTs JSON and returns the parsed body, also for a 4xx or 5xx response. */
async function post(path, body = {}) {
  let response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    return { httpStatus: 0, status: 'network_error', message: 'The server did not answer.' };
  }
  const data = await response.json().catch(() => undefined);
  if (typeof data?.status !== 'string' && !data?.authnParamsPublicKey) {
    // Not an answer from the app, for example a proxy's text 502 while the server restarts.
    const status = response.status >= 500 ? 'network_error' : 'error';
    return { httpStatus: response.status, status, message: `The server answered HTTP ${response.status}.` };
  }
  return { httpStatus: response.status, ...data };
}

// ─── Page helpers ───────────────────────────────────────────────────────────

function show(view) {
  for (const element of card.querySelectorAll('.view')) {
    element.hidden = element.id !== `view-${view}`;
  }
  focusView();
}

/** Keeps the keyboard focus in the visible view: on its first field, else on its main button. */
function focusView() {
  const view = card.querySelector('.view:not([hidden])');
  if (!view || view.contains(document.activeElement)) return;
  (view.querySelector('input, select') ?? view.querySelector('.btn-primary:not([hidden])'))?.focus();
}

function notify(text, tone = 'info') {
  const notice = $('notice');
  notice.textContent = text ?? '';
  notice.className = `notice ${tone}`;
  notice.hidden = !text;
}

function working(text) {
  notify();
  $('working-text').textContent = text;
  show('working');
}

function goHome(text, tone) {
  show('home');
  notify(text, tone);
}

// One action at a time: parallel finish requests could use up the attempts Auth0 allows.
let running = false;

async function run(action) {
  if (running) return;
  running = true;
  card.setAttribute('aria-busy', 'true');
  setButtonsDisabled(true);
  try {
    await action();
  } catch (error) {
    console.error(error);
    goHome(`Something went wrong: ${error.message}`, 'error');
  } finally {
    running = false;
    card.removeAttribute('aria-busy');
    setButtonsDisabled(false);
    focusView();
  }
}

function setButtonsDisabled(disabled) {
  for (const button of card.querySelectorAll('button')) {
    button.disabled = disabled;
  }
  $('passkey-login').disabled ||= !webauthn;
  $('passkey-signup').disabled ||= !webauthn;
}

// ─── Session ────────────────────────────────────────────────────────────────

/** Shows the profile when there is a session, else the home view. Returns whether the user is logged in. */
async function loadSession() {
  try {
    const response = await fetch('/api/session');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const { user } = await response.json();
    if (user) {
      renderProfile(user);
      return true;
    }
    goHome();
  } catch (error) {
    goHome(`The session could not be loaded (${error.message}). Reload the page.`, 'error');
  }
  return false;
}

function renderProfile(user) {
  const name = user.name || user.nickname || user.email || user.phone_number || user.sub;
  $('profile-name').textContent = name;
  $('profile-sub').textContent = user.email && user.email !== name ? user.email : 'You are logged in.';

  const avatar = $('avatar');
  avatar.replaceChildren();
  if (user.picture) {
    const image = document.createElement('img');
    image.src = user.picture;
    image.alt = '';
    avatar.append(image);
  } else {
    avatar.textContent = String(name).charAt(0).toUpperCase();
  }

  const facts = $('facts');
  facts.replaceChildren();
  const fact = (label, value, verified) => {
    if (!value) return;
    const term = document.createElement('dt');
    term.textContent = label;
    const detail = document.createElement('dd');
    detail.textContent = value;
    if (verified !== undefined) {
      const badge = document.createElement('span');
      badge.className = `badge ${verified ? 'ok' : 'no'}`;
      badge.textContent = verified ? 'verified' : 'not verified';
      detail.append(badge);
    }
    facts.append(term, detail);
  };
  fact('Email', user.email, user.email_verified);
  fact('Phone', user.phone_number, user.phone_number_verified);
  fact('User ID', user.sub);
  $('claims').textContent = JSON.stringify(user, null, 2);
  show('profile');
}

// ─── Passkey Login ──────────────────────────────────────────────────────────

async function passkeyLogin() {
  notify();
  working('Starting the passkey login…');
  const start = await post('/api/passkey/login/start');
  if (!start.authnParamsPublicKey) {
    goHome(start.message ?? 'The login could not start.', 'error');
    return;
  }

  working('Choose a passkey in the browser prompt…');
  let credential;
  try {
    credential = serialize(await navigator.credentials.get({ publicKey: requestOptions(start.authnParamsPublicKey) }));
  } catch (error) {
    goHome(webauthnMessage(error), 'error');
    return;
  }

  working('Logging you in…');
  await finish('login', { credential });
}

// ─── Passkey Signup ─────────────────────────────────────────────────────────

const signup = {
  profile: undefined, // what the form sent to the start route
  options: undefined, // authnParamsPublicKey of the latest start
  required: [], // verificationRequired of the latest start
  pending: [], // the identifiers that still need a code
  credential: undefined, // the serialized passkey, sent again with every retry
  verification: undefined, // the codes of the last attempt
  retries: 0,
};

function openSignup() {
  notify();
  show('signup');
}

function readSignupForm() {
  const form = $('view-signup').elements;
  const value = (name) => form[name].value.trim() || undefined;
  return {
    email: value('email'),
    phoneNumber: value('phoneNumber'),
    name: value('name'),
    deliveryMethod: value('phoneNumber') && value('deliveryMethod'),
  };
}

async function startSignup() {
  const profile = readSignupForm();
  if (!profile.email && !profile.phoneNumber) {
    notify('Enter an email address or a phone number.', 'error');
    return;
  }
  working('Starting the signup…');
  const start = await post('/api/passkey/signup/start', profile);
  if (!start.authnParamsPublicKey) {
    show('signup');
    notify(start.message ?? 'The signup could not start.', 'error');
    return;
  }
  Object.assign(signup, {
    profile,
    options: start.authnParamsPublicKey,
    required: start.verificationRequired ?? [],
    credential: undefined,
    verification: undefined,
    retries: 0,
  });
  if (signup.required.length > 0) {
    askForCodes(signup.required);
  } else {
    await createPasskeyAndFinish();
  }
}

/** Shows one code input for each identifier in the list. The others show as accepted. */
function askForCodes(identifiers, errorText) {
  signup.pending = identifiers;
  const plural = identifiers.length > 1;
  $('code-fields').replaceChildren(
    ...signup.required.map((id) => (identifiers.includes(id) ? codeInput(id) : acceptedRow(id)))
  );
  $('codes-title').textContent = plural ? 'Enter the codes' : 'Enter the code';
  $('codes-lead').textContent = signup.credential
    ? 'Your passkey is ready. Enter the code to finish.'
    : `Auth0 sent ${plural ? 'one-time codes' : 'a one-time code'}. ` +
      `Enter ${plural ? 'them' : 'it'} to create your passkey.`;
  $('codes-submit').textContent = signup.credential ? 'Verify' : 'Create passkey';
  // New codes mean a new flow, which only works before the passkey exists.
  $('resend').hidden = Boolean(signup.credential);
  show('codes');
  notify(errorText, 'error');
}

function codeInput(identifier) {
  const isEmail = identifier === 'email';
  const field = document.createElement('label');
  field.className = 'field otp';
  const title = document.createElement('span');
  title.textContent = isEmail ? 'Email code' : 'Phone code';
  const hint = document.createElement('small');
  const by = !isEmail && signup.profile.deliveryMethod === 'voice' ? ' by voice call' : '';
  hint.textContent = `Sent to ${isEmail ? signup.profile.email : signup.profile.phoneNumber}${by}`;
  const input = document.createElement('input');
  Object.assign(input, { name: identifier, inputMode: 'numeric', autocomplete: 'one-time-code', maxLength: 10 });
  field.append(title, hint, input);
  return field;
}

function acceptedRow(identifier) {
  const row = document.createElement('p');
  row.className = 'accepted';
  row.textContent = `${identifier === 'email' ? 'Email' : 'Phone'} code accepted`;
  return row;
}

async function submitCodes() {
  const verification = {};
  for (const identifier of signup.pending) {
    const code = $('code-fields').querySelector(`input[name="${identifier}"]`).value.trim();
    if (!code) {
      notify(`Enter the ${identifier} code.`, 'error');
      return;
    }
    verification[identifier] = code;
  }
  signup.verification = verification;
  if (!signup.credential) {
    await createPasskeyAndFinish();
    return;
  }
  working('Checking the code…');
  await finish('signup', { credential: signup.credential, verification });
}

async function createPasskeyAndFinish() {
  working('Create the passkey in the browser prompt…');
  try {
    signup.credential = serialize(await navigator.credentials.create({ publicKey: creationOptions(signup.options) }));
  } catch (error) {
    // The flow is still open, and the inputs still hold what the user typed: they can try again.
    show(signup.required.length > 0 ? 'codes' : 'signup');
    notify(webauthnMessage(error), 'error');
    return;
  }
  working('Creating your account…');
  await finish('signup', { credential: signup.credential, verification: signup.verification });
}

async function resendCodes() {
  working('Sending new codes…');
  const start = await post('/api/passkey/signup/start', signup.profile);
  if (!start.authnParamsPublicKey) {
    // Nothing was stored, so the codes already sent still work.
    show('codes');
    notify(start.message ?? 'New codes could not be sent.', 'error');
    return;
  }
  // A new flow: the old codes stop working, and the passkey must use the new options.
  Object.assign(signup, {
    options: start.authnParamsPublicKey,
    required: start.verificationRequired ?? [],
    retries: 0,
  });
  if (signup.required.length === 0) {
    await createPasskeyAndFinish();
    return;
  }
  askForCodes(signup.required);
  notify('New codes sent. Use the newest ones.', 'info');
}

// ─── Finishing a passkey flow ───────────────────────────────────────────────

let resendLater;

/** Sends the passkey (and the codes) to the server and acts on the status it returns. */
async function finish(flow, body) {
  let result = await post('/api/passkey/complete', body);
  if (result.status === 'failed' || result.status === 'network_error') {
    // After a server or network error the flow is still open: send the same request once more.
    const first = result;
    result = await post('/api/passkey/complete', body);
    if (result.status === 'restart') {
      // The first failure had ended the flow (for example Auth0 refused the passkey), so show its reason.
      result = first;
    }
  }

  switch (result.status) {
    case 'complete':
      if (await loadSession()) {
        const ready =
          flow === 'signup' ? 'Your account and passkey are ready.' : 'You are logged in with your passkey.';
        notify(ready, 'success');
      }
      return;
    case 'retry': {
      if (flow !== 'signup') {
        goHome('The passkey could not be used. Start again.', 'error');
        return;
      }
      // A wrong code: ask again for the identifiers still listed, and send the same passkey.
      const pending = result.verificationRequired?.length ? result.verificationRequired : signup.pending;
      if (++signup.retries > MAX_RETRIES) {
        goHome('Too many wrong codes. Start the signup again.', 'error');
        return;
      }
      const tryAgain =
        pending.length > 1 ? 'A code was wrong. Enter the codes again.' : 'That code was wrong. Try again.';
      askForCodes(pending, tryAgain);
      return;
    }
    case 'wait': {
      // Auth0 rate limited the request before it used the attempt: the same request can be sent again.
      resendLater = () => finish(flow, body);
      const seconds = result.retryAfterSeconds;
      const when = seconds ? `Try again in ${seconds} seconds.` : 'Wait a moment, then try again.';
      $('wait-text').textContent = `Auth0 is rate limiting these requests. ${when}`;
      show('wait');
      return;
    }
    case 'invalid':
      // The page always sends every code that is still needed, so this is a request the user cannot fix.
      goHome(sentence('The request was refused', result.message), 'error');
      return;
    case 'mfa_required':
      goHome(
        'Auth0 accepted the passkey, but this user must also complete MFA, which this example does not include. ' +
          'Use OIDC Login, or turn off MFA for this test.',
        'warn'
      );
      return;
    case 'restart':
      goHome(`This ${flow} is over: it expired, or a newer passkey flow started in another tab. Start again.`, 'warn');
      return;
    default:
      goHome(sentence('The passkey could not be used', result.message), 'error');
  }
}

/** "Lead: detail. Start again." for an error notice. */
const sentence = (lead, detail) => `${lead}${detail ? `: ${detail.replace(/\.?$/, '.')}` : '.'} Start again.`;

// ─── Wiring ─────────────────────────────────────────────────────────────────

$('passkey-login').addEventListener('click', () => run(passkeyLogin));
$('passkey-signup').addEventListener('click', openSignup);
$('view-signup').addEventListener('submit', (event) => {
  event.preventDefault();
  run(startSignup);
});
$('view-codes').addEventListener('submit', (event) => {
  event.preventDefault();
  run(submitCodes);
});
$('resend').addEventListener('click', () => run(resendCodes));
$('wait-retry').addEventListener('click', () =>
  run(async () => {
    working('Trying again…');
    await resendLater();
  })
);
for (const button of document.querySelectorAll('[data-home]')) {
  button.addEventListener('click', () => goHome());
}
$('view-signup').elements.phoneNumber.addEventListener('input', (event) => {
  $('delivery').hidden = !event.target.value.trim();
});

$('no-webauthn').hidden = webauthn;
setButtonsDisabled(false);

await loadSession();
